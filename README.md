# Rebecca-node

Rebecca-node is the agent that runs on each node server. It controls Xray and talks to the Rebecca panel over mutually authenticated gRPC.

## Install

The node connects to the panel with the certificate and token flow in the panel. Run this on the node server:

```bash
curl -sL https://raw.githubusercontent.com/rebeccapanel/Rebecca/master/scripts/rebecca/rebecca-node-binary.sh | sudo bash -s -- install
```

The installer creates a systemd service and downloads the release for the server's architecture.

- Dev channel: `curl -sL https://raw.githubusercontent.com/rebeccapanel/Rebecca/dev/scripts/rebecca/rebecca-node-binary.sh | sudo bash -s -- install --dev`
- Second node on the same server: add `--name rebecca-node2` to the install command.
- Commands: `rebecca-node help`

Always pipe the script into `sudo bash -s --` as shown. Running it as `sudo bash -c "$(curl ...)"` can fail with `Argument list too long`.

## Host requirements

OpenVPN and WireGuard set up their prerequisites on the node itself.

WireGuard, on first use, installs `wireguard-tools` and `nftables`, loads the kernel module, and creates one kernel interface per inbound. Traffic reaches Xray through nftables TPROXY, so the panel's routing rules still apply. NAT (MASQUERADE) is used only when the runtime sets `nat_enabled=true`.

## Build

CI builds binaries for every push to `dev`, every pull request, and every published release. Release assets cover Linux (`386`, `amd64`, `arm64`, `armv5`, `armv6`, `armv7`, `s390x`) and Windows `amd64`.

To build and test locally:

```bash
go run ./tools/build
go run ./tools/smoke
go test ./...
```
