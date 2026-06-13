# network-renderer-wireguard

`network-renderer-wireguard` emits WireGuard/OpenVPN-style provider runtime
material from explicit provider contracts.

It is a provider renderer, not a forwarding model.

Pipeline position: this repository is downstream of
`network-control-plane-model` provider contracts and upstream of runtime
consumers such as NixOS modules or lab orchestration.

Migration, deviation, exception, transition, or temporary compatibility behavior
must be explicit in the README, tests, and owning layer before it is accepted.

```text
network-forwarding-model -> network-control-plane-model -> network-renderer-wireguard
```

## Spec Chain

This renderer materializes WireGuard runtime output from explicit CPM provider contracts.
All behavior requirements originate from the FS-470 spec chain.

### Owning Chain: Remote Egress over WireGuard

| Layer | ID | Description |
|-------|----|-------------|
| URS   | Via FS-470 | Provider overlay transport — explicit policy-routed path |
| FS    | FS-470 | Remote Egress over WireGuard — explicit policy-routed path with fail-closed |
| HDS   | FS-470-HDS-010 | WireGuard Remote Egress hardware design — substrate facts (peer ID, tunnel readiness, overlay IPAM authority) |
| SDS   | FS-470-HDS-010-SDS-010 | WireGuard Remote Egress software design — architecture, failure boundaries, overlay identity + IPAM preservation |
| SMS   | FS-470-HDS-010-SDS-010-SMS-010 | **Coordinator** — WireGuard renderer module: `wg` binary in nix store, persistent WireGuard interface, service name `s88-provider-interface-wg-egress.service` (SMT: OK) |
| SMS   | FS-470-HDS-010-SDS-010-SMS-020 | Overlay IPAM binding — WireGuard addresses validate against overlay's IPAM authority |
| SMS   | FS-470-HDS-010-SDS-010-SMS-030 | Unrelated pool denial — no reuse of management/tenant/client-prefix pools |
| SMS   | FS-470-HDS-010-SDS-010-SMS-040 | Bootstrap payload separation — DNS/bootstrap facts separate from payload reachability |

### SMT Status (2026-06-12)

- FS-470-HDS-010-SDS-010-SMS-010 (Coordinator): **OK** — All child atoms tested at `network-renderer-wireguard@819faed`
- SMS-020 through SMS-040: **OK** — Full suite PASS
- All child SMS rows delegate to coordinator. Coordinator has no independent construction beyond child module contracts.

### Pipeline

```
network-labs (intent + inventory) → network-compiler → NFM → CPM → network-renderer-wireguard
```

Required inputs: Explicit CPM provider-neutral output (overlay runtime data, provider contracts). Per FS-983, the renderer consumes data through CPM output — it does not parse raw `intent.nix`, `inventory.nix`, or provider profile files for network meaning.

### SMS-010 Key Requirements

- Container definition MUST include `wg` binary in nix store closure
- Persistent WireGuard interface required (no bash wrapper that exits)
- Service name: `s88-provider-interface-wg-egress.service`

### Owning Repository

Construction tests: `network-renderer-wireguard/tests/`

## Contract

- The forwarding model and CPM/provider contract are the source of truth.
- This renderer consumes explicit provider runtime contracts and emits NixOS
  module material.
- Missing, partial, or inconsistent provider input must fail evaluation through
  visible assertions or missing-field errors.
- Renderer output must be deterministic for the same provider contract.

## Allowed

- Import WireGuard or OpenVPN provider profiles through NetworkManager from an
  explicit profile path and format.
- Render provider LAN, WAN, and VPN interface runtime material from explicit
  contract fields.
- Render source-scoped NAT44/NAT66, DHCPv4, RA/RDNSS, firewall, and health
  checks from explicit contract fields.

## Not Allowed

- Decide tenant forwarding, DNS leak policy, prefix ownership, public ingress,
  router GUA placement, or NAT66 mode locally.
- Infer behavior from provider names, profile contents, interface names, host
  defaults, examples, or current NetworkManager state.
- Treat a commercial imported VPN profile as public-ingress or routed-prefix
  capable unless that authority is explicit in the provider contract.
- Enable NAT66 for routed client GUA mode.

## API

The flake exports:

- `nixosModules.default`
- `nixosModules.wireguard-provider-runtime`
- `libBySystem.<system>.renderer.buildWireGuardProviderRenderResult`
- `libBySystem.<system>.renderer.buildWireGuardProviderRuntimeModule`
- `libBySystem.<system>.renderer.hostModule` — CPM-only NixOS module generator (wgInventory extracted from CPM model internally)

### hostModule (FS-470-HDS-010-SDS-010-SMS-021)

Accepts ONLY pre-compiled CPM output. `wgInventory` is extracted from the
CPM model internally — no separate parameter, no path-based API:

```nix
inputs.network-renderer-wireguard.libBySystem.${system}.renderer.hostModule {
  controlPlaneModel = ...;  # CPM control_plane_model output (REQUIRED)
  hostName = ...;           # host name (REQUIRED)
  # wgInventory extracted from controlPlaneModel.wgInventory internally
}
```

**CPM_GAP**: `controlPlaneModel` does not yet emit `wgInventory`. When absent,
no wireguard containers are created (graceful no-op). This gap must be closed
in `network-control-plane-model` before live WireGuard overlays can render.

### buildWireGuardProviderRenderResult / buildWireGuardProviderRuntimeModule

Example library use:

```nix
inputs.network-renderer-wireguard.libBySystem.${system}.renderer.buildWireGuardProviderRenderResult providerContract
inputs.network-renderer-wireguard.libBySystem.${system}.renderer.buildWireGuardProviderRuntimeModule providerContract
```

## S88 Layout

The renderer keeps provider projection logic in S88 ControlModule files:

- `s88/ControlModule/provider-contract.nix` validates and normalizes explicit provider contracts.
- `s88/ControlModule/firewall-nat.nix` projects contract-derived nft/NAT material.
- `s88/ControlModule/addressing-services.nix` projects DHCPv4 and RA/RDNSS service material.
- `s88/ControlModule/tunnel-runtime.nix` projects NetworkManager import, dispatcher, and health-check runtime material.
- `s88/ControlModule/render-result.nix` assembles the generic provider render result.

`modules/wireguard-provider-runtime.nix` binds those ControlModules into a
NixOS module. It must not regain provider semantics inline.

## Tests

Run:

```bash
./tests/test.sh
```
