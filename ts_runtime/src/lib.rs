#![doc = include_str!("../README.md")]

extern crate ts_netstack_smoltcp as netstack;

use std::sync::Arc;

use kameo::message::{Context, Message};
use tokio::sync::Mutex;
use ts_dataplane::async_tokio::{FromOverlay, Rx, ToOverlay, Tx};
use ts_transport::OverlayTransportId;

use crate::{
    control_runner::ControlRunner, dataplane::DataplaneActor, env::RegForwarded,
    multiderp::Multiderp, netstack_actor::NetstackActor, peer_tracker::PeerTracker,
};

/// Control runner.
pub mod control_runner;
mod dataplane;
mod derp_latency;
mod direct;
mod disco;
mod env;
mod error;
mod multiderp;
mod netmon;
mod netstack_actor;
mod packetfilter;
mod path_discoverer;
pub mod peer_tracker;
mod registry;
mod retained_bus;
mod route_updater;
mod src_filter;
mod stunner;
mod task;

pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use kameo::actor::{ActorRef, Spawn};
pub use registry::Registry;
pub use task::{ErasedTask, Task};

/// The runtime for a tailscale device.
pub struct Runtime {
    env: Env,
    packet_transport: Option<PacketTransport>,
}

/// Raw IP packet access to the overlay network, used to route advertised subnets.
///
/// Inbound packets addressed to an advertised subnet route arrive on `down`. Packets sent on `up`
/// (tagged with `id`) go through the outbound overlay router like netstack traffic.
pub struct PacketTransport {
    /// The id of this overlay transport.
    pub id: OverlayTransportId,
    /// Send packets into the dataplane.
    pub up: Tx<FromOverlay>,
    /// Receive packets from the dataplane.
    pub down: Rx<ToOverlay>,
}

/// Take the [`PacketTransport`] for advertised subnet routes.
///
/// Replies `None` if no routes are advertised or the transport was already taken.
#[derive(Debug, Copy, Clone)]
pub struct TakePacketTransport;

impl Message<TakePacketTransport> for Runtime {
    type Reply = Option<PacketTransport>;

    async fn handle(
        &mut self,
        _: TakePacketTransport,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.packet_transport.take()
    }
}

/// Configuration for starting a [`Runtime`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The control configuration to use.
    pub control_config: ts_control::Config,
    /// The auth key to use to connect to the control server.
    pub auth_key: Option<String>,
    /// The keys to use.
    pub keys: ts_keys::NodeState,
}

impl kameo::Actor for Runtime {
    type Error = Error;
    type Args = Config;

    async fn on_start(config: Config, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let env = Env::new(config.keys);

        env.bus.link(&slf).await;
        env.scheduler.link(&slf).await;
        env.registry.link(&slf).await;

        #[cfg(feature = "console")]
        {
            // Runs detached.
            if let Err(e) =
                kameo::console::serve((core::net::Ipv4Addr::new(127, 0, 0, 1), 9999)).await
            {
                tracing::error!(error = %e, "console died");
            };
        }

        DataplaneActor::supervise(&slf, env.clone()).spawn().await;

        let (netstack_id, netstack_up, netstack_down) = env
            .ask::<DataplaneActor, _>(None, dataplane::NewOverlayTransport, true)
            .await?;

        let advertise_routes = config.control_config.advertise_routes.clone();
        let packet_transport = if advertise_routes.is_empty() {
            None
        } else {
            let (id, up, down) = env
                .ask::<DataplaneActor, _>(None, dataplane::NewOverlayTransport, true)
                .await?;

            Some(PacketTransport { id, up, down })
        };

        disco::Disco::supervise(&slf, env.clone()).spawn().await;

        Multiderp::supervise(&slf, env.clone()).spawn().await;
        direct::DirectActor::supervise(&slf, env.clone())
            .spawn()
            .await;

        route_updater::RouteUpdater::supervise(
            &slf,
            (
                env.clone(),
                netstack_id,
                packet_transport.as_ref().map(|t| (t.id, advertise_routes)),
            ),
        )
        .spawn()
        .await;
        packetfilter::PacketfilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        src_filter::SourceFilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        stunner::Stunner::supervise(&slf, env.clone()).spawn().await;
        path_discoverer::PathDiscoverer::supervise(&slf, env.clone())
            .spawn()
            .await;

        if let Some(mon) = ts_netmon::platform_mon() {
            netmon::NetmonActor::supervise(&slf, (env.clone(), Arc::new(mon)))
                .spawn()
                .await;
        }

        PeerTracker::supervise(&slf, env.clone()).spawn().await;

        NetstackActor::supervise(
            &slf,
            (
                env.clone(),
                netstack::netcore::Config {
                    tcp_buffer_size: 64 * 1024,
                    command_channel_capacity: Some(128),
                    ..Default::default()
                },
                netstack_id,
                netstack_up,
                Arc::new(Mutex::new(netstack_down)),
            ),
        )
        .spawn()
        .await;

        control_runner::DialerActor::supervise(&slf, env.clone())
            .spawn()
            .await;

        ControlRunner::supervise(
            &slf,
            control_runner::Params {
                config: config.control_config,
                auth_key: config.auth_key,
                env: env.clone(),
            },
        )
        .spawn()
        .await;

        // Actors we forward messages for:
        env.wait::<ControlRunner>(None).await?;
        env.wait::<NetstackActor>(None).await?;
        env.wait::<PeerTracker>(None).await?;

        Ok(Self {
            env,
            packet_transport,
        })
    }
}

macro_rules! forward {
    ($actor:ty, $($msg:ty),* $(,)?) => {
        $(
            pub use $msg;

            impl kameo::message::Message<$msg> for Runtime {
                type Reply = RegForwarded<$actor, $msg>;

                async fn handle(
                    &mut self,
                    msg: $msg,
                    ctx: &mut Context<Self, Self::Reply>,
                ) -> RegForwarded<$actor, $msg> {
                    self.env.forward(ctx, None, msg).await
                }
            }
        )*
    };
}

forward!(NetstackActor, netstack_actor::GetChannel);
forward!(
    ControlRunner,
    control_runner::Ipv4,
    control_runner::Ipv6,
    control_runner::SelfNode,
    control_runner::AuthUrl,
);
forward!(
    PeerTracker,
    peer_tracker::PeerByName,
    peer_tracker::PeerByTailnetIp,
    peer_tracker::PeerByAcceptedRoute
);
