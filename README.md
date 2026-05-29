# network-renderer-wireguard

`network-renderer-wireguard` emits WireGuard/OpenVPN-style provider runtime
material from explicit provider contracts.

It is a provider renderer, not a forwarding model.

```text
network-forwarding-model -> network-control-plane-model -> network-renderer-wireguard
```

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
- `libBySystem.<system>.renderer.buildWireGuardProviderRuntimeModule`

Example library use:

```nix
inputs.network-renderer-wireguard.libBySystem.${system}.renderer.buildWireGuardProviderRuntimeModule providerContract
```

## Tests

Run:

```bash
./tests/test.sh
```
