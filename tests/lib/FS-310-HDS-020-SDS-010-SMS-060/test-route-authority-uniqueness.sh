#!/usr/bin/env bash
# GAMP-ID: FS-310-HDS-020-SDS-010-SMS-060
# GAMP-SCOPE: software-module-test
set -euo pipefail

# One route authority, one next-hop set — asserted on the tunnel peer set.
#
# URS "Canonical Realization and Renderer Boundary": a platform binding shall
# not create or duplicate routing. FS-310-HDS-020-SDS-010-SMS-060: "One
# route-selection authority shall have one modeled semantic next-hop set.
# Different next-hop sets for the same authority shall fail unless explicit
# multipath policy names the complete authorized member set," and renderers are
# "responsible for rejecting a conflict that reaches their input".
#
# In this renderer an authority is (interface, allowed-IP prefix). Two peers on
# one WireGuard interface both claiming 0.0.0.0/0 is one authority with two next
# hops: `wg` would install whichever peer was applied last, so the site's egress
# would depend on ordering. The renderer must reject that peer set.
#
# Coherence is enforced in both directions:
#   * single peer renders            -> required, else harness error;
#   * two peers claiming one prefix  -> must be rejected, else FAIL naming it.

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
trace_id="FS-310-HDS-020-SDS-010-SMS-060"
out="$(mktemp)"
trap 'rm -f "${out}"' EXIT

REPO_ROOT="${repo_root}" nix eval --impure --json --expr '
  let
    repoRoot = builtins.getEnv "REPO_ROOT";
    flake = builtins.getFlake ("path:" + repoRoot);
    system = builtins.currentSystem;
    pkgs = import flake.inputs.nixpkgs { inherit system; };
    lib = pkgs.lib;
    hostModule = flake.libBySystem.${system}.renderer.hostModule;

    mkPeer = i: {
      publicKey = "uK6fX6Hg5MR6pQOSRPFKCFH5hvQ5R8ymMjZtUsua3Q${toString i}=";
      endpoint = "198.51.100.${toString i}:51820";
      allowedIPs = [ "0.0.0.0/0" ];
    };

    evalNetdevs = peers:
      let
        rendererInput = { hostName = "s-router-nixos"; } // (import (repoRoot + "/tests/lib/wg-canonical.nix") ({
            wgInventory.wg-mini = {
              interface = "wg-mini";
              privateKeyFile = "/run/secrets/wireguard-mini-provider-private-key";
              listenPort = 51820;
              inherit peers;
            };
            data.acme.lab.overlays.wg-mini = {
              terminateOn = [ "wg-mini-node" ];
              providerBootstrapDns = [ ];
              nodes.wg-mini-node = { addr4 = "10.66.90.2/32"; addr6 = "fd42:66:90::2/128"; };
            };
          }));
        evaluated = import (flake.inputs.nixpkgs + "/nixos/lib/eval-config.nix") {
          inherit system;
          modules = [ (hostModule rendererInput) ];
        };
      in evaluated.config.containers.wg-mini-node.config.systemd.network.netdevs;

    force = peers: builtins.tryEval (builtins.deepSeq (evalNetdevs peers) true);
    baseline = force [ (mkPeer 1) ];
    conflict = force [ (mkPeer 1) (mkPeer 2) ];
  in {
    baselineOk = baseline.success;
    conflictRejected = !conflict.success;
  }
' >"${out}"

if [[ "$(jq -r '.baselineOk' "${out}")" != "true" ]]; then
  printf 'FAIL %s: harness error -- the single-peer baseline does not render, so a conflict result cannot be interpreted\n' "${trace_id}" >&2
  exit 1
fi

if [[ "$(jq -r '.conflictRejected' "${out}")" != "true" ]]; then
  printf 'FAIL %s: two peers on one interface both claim 0.0.0.0/0 and the renderer emitted both\n' "${trace_id}" >&2
  printf '  FS-310-HDS-020-SDS-010-SMS-060: one route authority shall have one semantic next-hop set; different next-hop sets shall fail.\n' >&2
  exit 1
fi

printf 'PASS %s (single-peer baseline renders; two peers claiming one prefix are rejected)\n' "${trace_id}"
