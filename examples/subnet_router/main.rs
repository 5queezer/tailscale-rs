//! Advertise a subnet route and forward its traffic through a Linux TUN device.

use std::{error::Error, net::Ipv4Addr, path::PathBuf, sync::Arc};

use clap::Parser;
use tailscale::{Config, Device};
use tracing_subscriber::filter::LevelFilter;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// The hostname this node will request.
    #[arg(short = 'H', long, default_value = "subnet_router_example")]
    hostname: Option<String>,

    /// The URL of the control URL to connect to.
    ///
    /// Uses the Tailscale control server by default if unspecified.
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,

    /// Subnet route(s) to advertise, e.g. `192.168.1.0/24`.
    #[arg(short = 'r', long = "route", required = true)]
    routes: Vec<ipnet::IpNet>,

    /// Name of the TUN device to create.
    #[arg(long, default_value = "tsrs0")]
    tun_name: String,

    /// Instead of creating a TUN device, answer ICMP echo requests for this address in userspace.
    ///
    /// Needs no root or `CAP_NET_ADMIN`; useful to test the route from a tailnet peer with `ping`.
    #[arg(long)]
    echo: Option<Ipv4Addr>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let mut config = Config::default_with_key_file(&args.key_file).await?;
    config.requested_hostname = args.hostname;
    config.advertise_routes = args.routes;

    if let Some(url) = args.control_url {
        config.control_server_url = url;
    }

    let dev = Device::new(&config, args.auth_key).await?;
    let mut router = dev
        .take_subnet_router()
        .await?
        .ok_or("no subnet router: no routes advertised")?;

    if let Some(addr) = args.echo {
        tracing::info!(%addr, "answering ICMP echo requests");

        loop {
            let mut packet = router.recv().await?;
            if icmp_echo_reply(&mut packet, addr) {
                router.send(&packet).await?;
            }
        }
    }

    let tun = Arc::new(
        tun_rs::DeviceBuilder::new()
            .name(&args.tun_name)
            .mtu(1280)
            .build_async()?,
    );

    tracing::info!(tun = %args.tun_name, "forwarding subnet traffic");

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            // Tailnet -> TUN: the kernel forwards these on to the subnet.
            packet = router.recv() => {
                tun.send(&packet?).await?;
            }
            // TUN -> tailnet: replies from the subnet, routed to the tailnet via the TUN.
            n = tun.recv(&mut buf) => {
                router.send(&buf[..n?]).await?;
            }
        }
    }
}

/// Turn an IPv4 ICMP echo request for `addr` into the matching echo reply, in place.
///
/// Returns `false` (leaving `packet` unchanged) if it isn't such a request.
fn icmp_echo_reply(packet: &mut [u8], addr: Ipv4Addr) -> bool {
    let Some(&first) = packet.first() else {
        return false;
    };
    let ihl = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4
        || packet.len() < ihl + 8
        || packet[9] != 1 // ICMP
        || packet[16..20] != addr.octets()
        || packet[ihl] != 8
    // echo request
    {
        return false;
    }

    // Swap source and destination; this doesn't change the IPv4 header checksum.
    let (src, dst) = packet[12..20].split_at_mut(4);
    src.swap_with_slice(dst);

    let icmp = &mut packet[ihl..];
    icmp[0] = 0; // echo reply
    icmp[2..4].fill(0);
    let sum = checksum(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    true
}

/// The internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
