# Example: Subnet Router

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

A [subnet router](https://tailscale.com/docs/features/subnet-routers) that advertises one or more
routes and forwards their traffic through a Linux TUN device, letting the kernel route it to the
local network.

Inbound tailnet traffic for an advertised route is written to the TUN device; anything the kernel
routes into the TUN device is sent to the tailnet. Run the example on a different machine (or
VM/container) than the Tailscale client you'll test from, since both want to route the tailnet's
address range. It needs `CAP_NET_ADMIN` to create the TUN device, so it's easiest to build it first
and run the binary with `sudo`:

```sh
# Terminal 1
$ cargo build --example subnet_router
$ sudo ./target/debug/examples/subnet_router --auth-key $AUTH_KEY --route 192.168.1.0/24
```

Then set up IPv4 forwarding on the same host (replace `eth0` with the interface facing
`192.168.1.0/24`):

```sh
# Terminal 2
$ sudo ip link set tsrs0 up
# Return traffic for tailnet peers goes back through the TUN device.
$ sudo ip route add 100.64.0.0/10 dev tsrs0
# Forward between the TUN device and the LAN, masquerading tailnet sources.
$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -o eth0 -j MASQUERADE
```

Approve the route for `subnet_router_example` in the admin console (or with an
[auto-approver](https://tailscale.com/docs/reference/syntax/policy-file#auto-approvers)), make sure
the tailnet policy allows your local machine to access `192.168.1.0/24`, and enable accepting routes
on your local machine (`tailscale set --accept-routes` on Linux). Hosts on `192.168.1.0/24` should
now be reachable from your local machine.

## Testing without root

With `--echo`, the example skips the TUN device and answers ICMP echo requests for a single address
in userspace, so it needs no special privileges:

```sh
$ cargo run --example subnet_router -- --auth-key $AUTH_KEY --route 10.250.0.0/24 --echo 10.250.0.1
```

After approving the route and accepting routes on your local machine, `ping 10.250.0.1` should get
replies.
