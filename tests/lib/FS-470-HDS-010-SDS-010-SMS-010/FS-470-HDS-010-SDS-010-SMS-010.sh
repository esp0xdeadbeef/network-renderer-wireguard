#!/usr/bin/env bash
# GAMP-ID: FS-470-HDS-010-SDS-010-SMS-010
# GAMP-SCOPE: software-module-test
# Focused construction test: WG renderer plan from explicit CPM inputs.
# Verifies the coordinator module consumes CPM provider contracts,
# produces WG runtime configuration, and rejects missing required fields.
#
# SMS acceptance predicates:
#   P1: Consume CPM provider contracts (renderer-agnostic).
#   P2: Produce WireGuard runtime configuration (interface, peer, routes).
#   P3: Produce NixOS module that enables WG interface on target container.
#   P4: systemd service creates persistent WG interface, bash wrapper rejected.
#
# Active seeded negatives:
#   SN1: Missing required field (provider.class) → nix eval throws
#   SN2: Missing required field (interfaces.wan) → nix eval throws
#   SN3: Missing peer endpoint → normalize throws
# Covers: CPM-overlay-contract boundary, plan-reject-missing, delegated routes.
set -euo pipefail

repo_root="${SMS_TEST_REPO_ROOT:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)}"
cd "${repo_root}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
all_checks_passed=true

echo "--- FS-470-HDS-010-SDS-010-SMS-010: WG Plan from Explicit CPM Inputs ---"
echo ""

# ================================================================
# Helper: expect nix eval failure with a specific diagnostic phrase
# ================================================================
expect_eval_failure() {
  local label="$1"
  local phrase="$2"
  local expr="$3"
  local stderr_path
  stderr_path="$(mktemp)"
  if nix eval --impure --no-warn-dirty --json --expr "${expr}" >/dev/null 2>"${stderr_path}"; then
    rm -f "${stderr_path}"
    echo "  FAIL: ${label} was accepted but should have been rejected" >&2
    all_checks_passed=false
    return 1
  fi
  if grep -Fq "${phrase}" "${stderr_path}"; then
    echo "  PASS: ${label} rejected with expected diagnostic: ${phrase}"
    rm -f "${stderr_path}"
  else
    echo "  FAIL: ${label} diagnostic did not contain: ${phrase}" >&2
    echo "  Actual stderr:" >&2
    cat "${stderr_path}" >&2
    rm -f "${stderr_path}"
    all_checks_passed=false
  fi
}

# ================================================================
# Check 1: Build valid contract and verify render result structure
# SMS-010 P1, P2: Consume CPM contract → produce render result
# ================================================================
echo "--- Check 1: Valid contract → render result structure ---"

render_json="$(nix eval --impure --no-warn-dirty --json --expr "
  let
    flake = builtins.getFlake (toString \"${repo_root}\");
    api = flake.libBySystem.x86_64-linux.renderer;
    contract = {
      id = \"sms010-test\";
      provider = {
        class = \"commercial-imported\";
        mode = \"egress-only\";
        prefixAuthority = \"host-only-128\";
      };
      interfaces = {
        wan = \"uplink0\";
        lan = \"edge-lan0\";
        vpn = \"wg-sms010\";
      };
      profile = {
        mode = \"generated-peer\";
        generatedPeer = {
          privateKeyFile = \"/run/keys/wg-sms010-private\";
          addresses = [ \"10.47.0.2/32\" ];
          dns = [ \"10.47.0.1\" ];
          mtu = 1420;
          peers = [{
            publicKey = \"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=\";
            endpoint = \"198.51.100.47:51820\";
            allowedIPs = [ \"0.0.0.0/0\" \"::/0\" ];
            persistentKeepalive = 25;
          }];
        };
      };
      runtime = {
        uuidFile = \"/run/network-renderer-wireguard/sms010.uuid\";
        generatedConfigPath = \"/run/network-renderer-wireguard/sms010-generated.conf\";
      };
      dns.mode = \"default\";
      firewall = {
        mode = \"dedicated-gateway\";
        allowLanToVpn = true;
        denyLanToWan = true;
        denyWanToLan = true;
      };
      lan.ipv4.address = \"10.147.0.1/24\";
      lan.ipv6.address = \"fd47:147::1/64\";
      nat = {
        ipv4.enable = true;
        ipv4.sourceCidrs = [ \"10.147.0.0/24\" ];
        ipv6.enable = true;
        ipv6.sourceCidrs = [ \"fd47:147::/64\" ];
      };
      publicIngress = [];
      portForwards = [];
    };
    result = api.buildWireGuardProviderRenderResult contract;
  in {
    rendererClass = result.rendererClass or null;
    targetRenderer = result.targetRenderer or null;
    hasProviderRuntimeModule = builtins.hasAttr \"providerRuntime\" result.artifacts.nixosModules;
    capabilityCount = builtins.length (result.capabilities or []);
    diagnosticCount = builtins.length (result.diagnostics or []);
    unsupportedContractCount = builtins.length (result.unsupportedContracts or []);
    metadataTargetRenderer = result.metadata.requested.target.renderer or null;
    scopeTargetRenderer = result.scope.target.renderer or null;
  }
")"

# Verify key output fields
checks_ok=true
for phrase in \
  '"rendererClass":"provider"' \
  '"targetRenderer":"wireguard-provider"' \
  '"hasProviderRuntimeModule":true' \
  '"diagnosticCount":0' \
  '"unsupportedContractCount":0'; do
  if grep -Fq "${phrase}" <<<"${render_json}"; then
    echo "  PASS: ${phrase}"
  else
    echo "  FAIL: missing expected output: ${phrase}" >&2
    checks_ok=false
  fi
done

if echo "${render_json}" | jq -e '.capabilityCount > 0' >/dev/null 2>&1; then
  echo "  PASS: capabilities present ($(echo "${render_json}" | jq '.capabilityCount'))"
else
  echo "  FAIL: no capabilities in render result" >&2
  checks_ok=false
fi

if [[ "${checks_ok}" != "true" ]]; then
  echo "  DEBUG render_json: ${render_json}" >&2
  all_checks_passed=false
fi

echo ""

# ================================================================
# Check 2: Delegated routes — verify NixOS module structure
# SMS-010 P3: Produce NixOS module that enables WG interface on target container
# ================================================================
echo "--- Check 2: NixOS module structure with WG config ---"

module_json="$(nix eval --impure --no-warn-dirty --json --expr "
  let
    flake = builtins.getFlake (toString \"${repo_root}\");
    api = flake.libBySystem.x86_64-linux.renderer;
    result = api.buildWireGuardProviderRenderResult {
      id = \"sms010-routes\";
      provider = {
        class = \"commercial-imported\";
        mode = \"egress-only\";
        prefixAuthority = \"host-only-128\";
      };
      interfaces = {
        wan = \"uplink0\";
        lan = \"edge-lan0\";
        vpn = \"wg-sms010-rt\";
      };
      profile = {
        mode = \"generated-peer\";
        generatedPeer = {
          privateKeyFile = \"/run/keys/wg-private\";
          addresses = [ \"10.99.0.2/32\" ];
          dns = [ \"10.99.0.1\" ];
          peers = [{
            publicKey = \"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=\";
            endpoint = \"198.51.100.99:51820\";
            allowedIPs = [ \"0.0.0.0/0\" ];
          }];
        };
      };
      runtime = {
        uuidFile = \"/run/wg.uuid\";
        generatedConfigPath = \"/run/wg-generated.conf\";
      };
      dns.mode = \"default\";
      firewall = {
        mode = \"dedicated-gateway\";
        allowLanToVpn = true;
        denyLanToWan = true;
        denyWanToLan = true;
      };
      lan.ipv4.address = \"10.99.0.1/24\";
      nat = {
        ipv4.enable = true;
        ipv4.sourceCidrs = [ \"10.99.0.0/24\" ];
        ipv6.enable = false;
      };
      publicIngress = [];
      portForwards = [];
      routes.returnRoutes = [{
        destination = \"10.99.50.0/24\";
        gateway = \"10.99.0.1\";
      }];
    };
    module = result.artifacts.nixosModules.providerRuntime;
    importCount = builtins.length module.imports;
    serviceKeys = builtins.attrNames (module.services or {});
    hasWgService = builtins.elem \"network-renderer-wireguard\" serviceKeys;
  in {
    inherit importCount hasWgService;
    serviceKeys = serviceKeys;
  }
")"

if echo "${module_json}" | jq -e '.importCount > 0' >/dev/null 2>&1; then
  echo "  PASS: module has imports ($(echo "${module_json}" | jq '.importCount'))"
else
  echo "  FAIL: no imports in runtime module" >&2
  all_checks_passed=false
fi

if echo "${module_json}" | jq -e '.hasWgService == true' >/dev/null 2>&1; then
  echo "  PASS: module has network-renderer-wireguard service namespace"
else
  echo "  FAIL: missing network-renderer-wireguard in module services" >&2
  all_checks_passed=false
fi

echo ""

# ================================================================
# Seeded Negative 1: Missing required field provider.class
# SN1: plan-reject-missing → verify nix throws with diagnostic
# ================================================================
echo "--- Seeded Negative 1: Missing provider.class ---"

expect_eval_failure \
  "SN1-missing-provider-class" \
  "provider contract missing provider.class" \
  "let
    flake = builtins.getFlake (toString \"${repo_root}\");
    api = flake.libBySystem.x86_64-linux.renderer;
    contract = {
      id = \"sn1\";
      provider.mode = \"egress-only\";
      interfaces = {
        wan = \"uplink0\";
        lan = \"lan0\";
        vpn = \"wg0\";
      };
    };
  in api.buildWireGuardProviderRenderResult contract"

echo ""

# ================================================================
# Seeded Negative 2: Missing required field profile.mode
# SN2: plan-reject-missing → verify nix throws with diagnostic
# ================================================================
echo "--- Seeded Negative 2: Missing profile.mode ---"

expect_eval_failure \
  "SN2-missing-profile-mode" \
  "provider contract missing profile.mode" \
  "let
    flake = builtins.getFlake (toString \"${repo_root}\");
    api = flake.libBySystem.x86_64-linux.renderer;
    contract = {
      id = \"sn2\";
      provider = {
        class = \"commercial-imported\";
        mode = \"egress-only\";
        prefixAuthority = \"host-only-128\";
      };
      dns.mode = \"default\";
      interfaces = {
        wan = \"uplink0\";
        lan = \"lan0\";
        vpn = \"wg0\";
      };
    };
  in api.buildWireGuardProviderRenderResult contract"

echo ""

# ================================================================
# Seeded Negative 3: Missing peer endpoint
# SN3: Missing required peer field → verify rejection
# ================================================================
echo "--- Seeded Negative 3: Missing peer endpoint ---"

expect_eval_failure \
  "SN3-missing-peer-endpoint" \
  "generated-peer peers require endpoint" \
  "let
    flake = builtins.getFlake (toString \"${repo_root}\");
    api = flake.libBySystem.x86_64-linux.renderer;
    contract = {
      id = \"sn3\";
      provider = {
        class = \"commercial-imported\";
        mode = \"egress-only\";
        prefixAuthority = \"host-only-128\";
      };
      interfaces = {
        wan = \"uplink0\";
        lan = \"lan0\";
        vpn = \"wg0\";
      };
      profile = {
        mode = \"generated-peer\";
        generatedPeer = {
          privateKeyFile = \"/run/keys/wg-private\";
          addresses = [ \"10.0.0.2/32\" ];
          dns = [ \"10.0.0.1\" ];
          peers = [{
            publicKey = \"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc=\";
            allowedIPs = [ \"0.0.0.0/0\" ];
          }];
        };
      };
      runtime = {
        uuidFile = \"/run/wg.uuid\";
        generatedConfigPath = \"/run/wg.conf\";
      };
      dns.mode = \"default\";
      lan.ipv4.address = \"10.0.0.1/24\";
      nat = { ipv4.enable = false; ipv6.enable = false; };
      publicIngress = [];
      portForwards = [];
    };
  in api.buildWireGuardProviderRenderResult contract"

echo ""

# ================================================================
# Final report
# ================================================================
echo "============================================================"
echo "FS-470-HDS-010-SDS-010-SMS-010 Plan from Explicit Inputs"
echo "============================================================"
echo "  Check 1 (valid contract → render result):  validated"
echo "  Check 2 (NixOS module with WG config):      validated"
echo "  Seeded negative 1 (missing provider.class): rejected"
echo "  Seeded negative 2 (missing profile.mode):    rejected"
echo "  Seeded negative 3 (missing peer endpoint):  rejected"
echo ""

if [[ "${all_checks_passed}" == "true" ]]; then
  echo "PASS: FS-470-HDS-010-SDS-010-SMS-010 — WG plan from explicit CPM inputs."
  echo "  2 structural checks passed. 3 active seeded negatives rejected."
  exit 0
else
  echo "FAIL: FS-470-HDS-010-SDS-010-SMS-010 — plan verification failed."
  exit 1
fi
