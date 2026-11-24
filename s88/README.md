# network-renderer-wireguard S88 Boundary

`network-renderer-wireguard` owns the projection of a validated canonical
realization bundle into WireGuard provider-runtime configuration
(FS-470-HDS-010-SDS-010-SMS-010 and its child rows). The bundle carries the
released network-control-plane artifact plus the overlay's provider contract;
the renderer reads those and never reads raw intent, inventory, an unvalidated
CPM payload, or a provider profile file for network meaning (FS-983, FS-166).

## Enterprise

Not present as a directory. The renderer is handed the overlay facts it must
render -- which overlays exist, their provider contracts, their node
addresses -- and it does not choose an enterprise or a site. There is nothing
here to scope, so an empty Enterprise level would only restate the Site level.

## Site

Not present as a directory, for the same reason: site selection has already
happened upstream. A site-shaped decision made here would be the renderer
deriving network meaning from a name.

## Unit

Not present as a directory. There is one rendered unit of work per provider
overlay, and it is expressed as a NixOS module option
(`services.network-renderer-wireguard.providerRuntime`) rather than as a
per-unit file tree.

## ControlModule

`s88/ControlModule/` -- the five pure modules that turn one normalized provider
state into the things a host needs:

| file | responsibility |
| --- | --- |
| `provider-contract.nix` | normalize and assert the provider contract; fail closed |
| `addressing-services.nix` | DHCPv4 client and radvd configuration |
| `firewall-nat.nix` | nftables filter and NAT rules for the tunnel path |
| `tunnel-runtime.nix` | wireguard-quick config text, dispatcher and health services |
| `render-result.nix` | the shape a caller gets back |

## EquipmentModule / Phase

Not present. A WireGuard provider runtime has no equipment or process structure
of its own.

## Entrypoints

- `flake.nix` -- `nixosModules.default` and `libBySystem`.
- `modules/wireguard-provider-runtime.nix` -- the NixOS module. It lives outside
  `s88/` and imports four of the five ControlModule files; the fifth
  (`render-result.nix`) is imported by `flake.nix` and by the
  FS-470-HDS-010-SDS-010-SMS-080 test.

The S88 graph test follows that module transitively. A walk that stopped at the
level tree reported all three ControlModule files reached only through it as
unreachable, which is a property of the walk, not of the tree.
