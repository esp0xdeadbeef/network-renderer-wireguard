{ lib, pkgs }:

let
  line = text: ''printf '%s\n' ${lib.escapeShellArg text} >> "$CONF"'';
  optionalLine = condition: text: lib.optionalString condition "${line text}\n";
  generatedPeerScript =
    state:
    lib.optionalString (state.profileMode == "generated-peer") (
      let
        generated = state.generatedPeerForScript;
        addressLines =
          if generated.addressesFile != null then
            ''printf 'Address = %s\n' "$(cat ${lib.escapeShellArg generated.addressesFile})" >> "$CONF"''
          else
            lib.concatMapStringsSep "\n" (address: line "Address = ${address}") generated.addresses;
        # The provider DNS is only reachable through the tunnel, so it must
        # not be written into the imported connection's resolv.conf before the
        # tunnel is up — otherwise the endpoint hostname is queried against the
        # tunnel's own DNS and the handshake can never start. The recursive
        # resolver reads the same dnsFile directly for its forward-zone.
        dnsLines = "";
        mtuLines = optionalLine (generated.mtu != null) "MTU = ${toString generated.mtu}";
        peerScript =
          peer:
          lib.concatStringsSep "\n" (
            [
              (line "")
              (line "[Peer]")
              (
                if peer.publicKeyFile != null then
                  ''printf 'PublicKey = %s\n' "$(cat ${lib.escapeShellArg peer.publicKeyFile})" >> "$CONF"''
                else
                  line "PublicKey = ${peer.publicKey}"
              )
              (
                if peer.endpointFile != null then
                  ''printf 'Endpoint = %s\n' "$(cat ${lib.escapeShellArg peer.endpointFile})" >> "$CONF"''
                else
                  line "Endpoint = ${peer.endpoint}"
              )
              (line "AllowedIPs = ${lib.concatStringsSep ", " peer.allowedIPs}")
            ]
            ++ lib.optional (peer.presharedKeyFile != null) ''
              printf 'PresharedKey = %s\n' "$(cat ${lib.escapeShellArg peer.presharedKeyFile})" >> "$CONF"
            ''
            ++ lib.optional (peer.persistentKeepalive != null) (
              line "PersistentKeepalive = ${toString peer.persistentKeepalive}"
            )
          );
        peerScripts = lib.concatMapStringsSep "\n" peerScript generated.peers;
      in
      ''
        mkdir -p "$(dirname "$CONF")"
        umask 077
        : > "$CONF"
        ${line "[Interface]"}
        printf 'PrivateKey = %s\n' "$(cat ${lib.escapeShellArg generated.privateKeyFile})" >> "$CONF"
        ${addressLines}
        ${dnsLines}
        ${mtuLines}
        ${peerScripts}
      ''
    );
in
{
  wanConnectionText = state: ''
    [connection]
    id=${state.wanInterface}
    type=ethernet
    interface-name=${state.wanInterface}
    autoconnect=true
    permissions=

    [ipv4]
    method=${state.wanIPv4Method}
    ${lib.optionalString (state.wanIPv4RouteMetric != null) "route-metric=${state.wanIPv4RouteMetric}"}

    [ipv6]
    method=${state.wanIPv6Method}
    ${lib.optionalString (state.wanIPv6RouteMetric != null) "route-metric=${state.wanIPv6RouteMetric}"}
  '';

  dispatcherService = state: {
    description = "Bring up provider tunnel ${state.vpnInterface} from model/provider contract";
    after = [ "NetworkManager-wait-online.service" ];
    requires = [ "NetworkManager-wait-online.service" ];
    wantedBy = [ "multi-user.target" ];

    path = with pkgs; [
      coreutils
      gawk
      gnugrep
      iproute2
      networkmanager
      networkmanager-openvpn
      wireguard-tools
    ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      Restart = "on-failure";
      RestartSec = 10;

      ExecStart = pkgs.writeShellScript "wireguard-provider-dispatcher-start" ''
        set -euo pipefail
        CONF=${lib.escapeShellArg state.profilePath}
        IFACE=${lib.escapeShellArg state.vpnInterface}
        LAN=${lib.escapeShellArg state.lanInterface}
        FORMAT=${lib.escapeShellArg state.profileFormat}
        UUID_FILE=${lib.escapeShellArg state.uuidFile}

        ${generatedPeerScript state}

        test -s "$CONF" || {
          echo "[wireguard-provider] missing provider profile: $CONF" >&2
          exit 1
        }

        if nmcli -t -f NAME con show | grep -qx "$IFACE"; then
          nmcli con down "$IFACE" || true
          nmcli con delete "$IFACE" || true
        fi

        BEFORE=$(nmcli -t -f UUID con show | sort || true)

        case "$FORMAT" in
          wireguard)
            nmcli connection import type wireguard file "$CONF"
            ;;
          openvpn)
            nmcli connection import type openvpn file "$CONF"
            ;;
          *)
            echo "[wireguard-provider] unsupported profile format from contract: $FORMAT" >&2
            exit 1
            ;;
        esac

        AFTER=$(nmcli -t -f UUID con show | sort)
        NEW_UUID=$(comm -13 <(printf "%s\n" "$BEFORE") <(printf "%s\n" "$AFTER") | tail -n1)
        if [ -z "''${NEW_UUID:-}" ]; then
          echo "[wireguard-provider] could not determine imported connection UUID" >&2
          exit 1
        fi

        nmcli con modify "$NEW_UUID" connection.id "$IFACE"
        nmcli con modify "$NEW_UUID" connection.interface-name "$IFACE"
        nmcli con modify "$NEW_UUID" connection.autoconnect yes
        nmcli con up "$NEW_UUID"
        echo "$NEW_UUID" > "$UUID_FILE"

        for _ in $(seq 1 20); do
          if ip link show "$IFACE" >/dev/null 2>&1; then
            # The provider's own encrypted outer packets are fwmark-marked by
            # NetworkManager. Route them through the main table so the
            # handshake reaches the provider via the underlay, instead of
            # falling into the modeled DNS egress table whose dev-overlay
            # default would feed them straight back into this tunnel.
            fwmark=$(wg show "$IFACE" fwmark)
            if [ -n "$fwmark" ] && [ "$fwmark" != "off" ]; then
              ip rule add priority 32700 fwmark "$fwmark" lookup main 2>/dev/null || true
              ip -6 rule add priority 32700 fwmark "$fwmark" lookup main 2>/dev/null || true
              echo "[wireguard-provider] fwmark $fwmark routed via main table" >&2
            fi
            ip link set "$LAN" up 2>/dev/null || true
            echo "[wireguard-provider] tunnel $IFACE up; lan $LAN ready" >&2
            systemctl start wireguard-provider-ready.target
            exit 0
          fi
          sleep 1
        done

        echo "[wireguard-provider] interface did not appear: $IFACE" >&2
        exit 1
      '';

      ExecStop = pkgs.writeShellScript "wireguard-provider-dispatcher-stop" ''
        set -euo pipefail
        UUID_FILE=${lib.escapeShellArg state.uuidFile}
        # The upstream-selector owns the lane gating; the core never brings
        # its fabric link down (that would also tear down the routing the
        # tunnel needs to recover).
        if [ -f "$UUID_FILE" ]; then
          UUID=$(cat "$UUID_FILE")
          nmcli con down "$UUID" || true
          nmcli con delete "$UUID" || true
          rm -f "$UUID_FILE"
        else
          nmcli con down ${lib.escapeShellArg state.vpnInterface} || true
          nmcli con delete ${lib.escapeShellArg state.vpnInterface} || true
        fi
      '';
    };
  };

  healthService = state: {
    description = "Keep the provider tunnel up and withdraw the fabric lane on loss";
    after = [ "wireguard-provider-ready.target" ];
    requires = [ "wireguard-provider-ready.target" ];
    path = with pkgs; [
      coreutils
      gnugrep
      iproute2
      iputils
    ];
    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = 2;
      ExecStart = pkgs.writeShellScript "wireguard-provider-health" ''
        set -euo pipefail
        iface=${lib.escapeShellArg state.vpnInterface}
        lan=${lib.escapeShellArg state.lanInterface}
        dnsFile=${lib.escapeShellArg (state.generatedDnsFile or "")}

        # The probe targets are the provider's in-tunnel DNS gateways read from
        # the profile dnsFile (a runtime fact), never a hardcoded address. Both
        # families are probed because the lane carries IPv4 and IPv6 together.
        probe4=""
        probe6=""
        if [ -n "$dnsFile" ] && [ -f "$dnsFile" ]; then
          probe4="$(tr ',' '\n' < "$dnsFile" | grep -E '^[0-9]+[.]' | head -1)"
          probe6="$(tr ',' '\n' < "$dnsFile" | grep -E ':' | head -1)"
        fi
        if [ -z "$probe4" ] && [ -z "$probe6" ]; then
          echo "[wireguard-provider-health] no in-tunnel probe targets in $dnsFile" >&2
          exit 0
        fi

        # Withdraw the lane after three consecutive misses on every configured
        # family (BFD-style detect multiplier), and restore it on the first hit
        # so the upstream-selector's ECMP re-hashes to the remaining cores.
        state="up"
        misses=0
        while true; do
          ok=0
          if [ -n "$probe4" ] && ${pkgs.iputils}/bin/ping -c1 -W1 -I "$iface" "$probe4" >/dev/null 2>&1; then
            ok=1
          fi
          if [ -n "$probe6" ] && ${pkgs.iputils}/bin/ping -6 -c1 -W1 -I "$iface" "$probe6" >/dev/null 2>&1; then
            ok=1
          fi

          if [ "$ok" = "1" ]; then
            misses=0
            if [ "$state" != "up" ]; then
              ip link set "$lan" up 2>/dev/null || true
              state="up"
              echo "[wireguard-provider-health] $iface egress recovered; restored lane $lan" >&2
            fi
          else
            misses=$((misses + 1))
            if [ "$misses" -ge 3 ] && [ "$state" != "down" ]; then
              ip link set "$lan" down 2>/dev/null || true
              state="down"
              echo "[wireguard-provider-health] $iface egress failed; withdrew lane $lan" >&2
            fi
          fi
          sleep 0.3
        done
      '';
    };
  };
}
