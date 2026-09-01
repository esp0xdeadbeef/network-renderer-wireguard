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
  wanConnectionText =
    state:
    ''
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

  dispatcherService =
    state:
    {
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
              echo "[wireguard-provider] tunnel $IFACE up; un-gated lan $LAN" >&2
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
          LAN=${lib.escapeShellArg state.lanInterface}
          # Gate the fabric link so the upstream-selector ECMP drops this core
          # while the tunnel is down instead of black-holing tenant traffic.
          if ip link show "$LAN" >/dev/null 2>&1; then
            ip link set "$LAN" down 2>/dev/null || true
            echo "[wireguard-provider] tunnel stopping; gated lan $LAN down (ECMP failover)" >&2
          fi
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

  healthService =
    state:
    {
      description = "Check provider tunnel health and gate the LAN fabric link";
      after = [ "wireguard-provider-ready.target" ];
      requires = [ "wireguard-provider-ready.target" ];
      path = with pkgs; [
        iproute2
        gawk
        wireguard-tools
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "wireguard-provider-health" ''
          set -euo pipefail
          iface=${lib.escapeShellArg state.vpnInterface}
          lan=${lib.escapeShellArg state.lanInterface}
          rx_path="/sys/class/net/$iface/statistics/rx_bytes"

          bring_lan_down() {
            if ip link show "$lan" >/dev/null 2>&1; then
              ip link set "$lan" down
              echo "[wireguard-provider-health] tunnel $iface unhealthy; brought $lan down for ECMP failover" >&2
            fi
          }

          if [ ! -d "/sys/class/net/$iface" ]; then
            echo "[wireguard-provider-health] $iface missing; gating $lan and restarting dispatcher" >&2
            bring_lan_down
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          if [ ! -r "$rx_path" ]; then
            echo "[wireguard-provider-health] cannot read $rx_path; gating $lan and restarting dispatcher" >&2
            bring_lan_down
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          # The definitive tunnel-health signal is the WireGuard handshake
          # age: a healthy peer re-handshakes every persistent-keepalive
          # interval (15s), so a handshake younger than a few keepalives means
          # the tunnel is alive. The old RX-delta + ICMP heuristic
          # false-negatives on an idle tunnel (the 5s RX window misses the 15s
          # keepalive response two thirds of the time) or on an ICMP-filtered
          # target, which gated the fabric link after every deploy and caused
          # intermittent drops.
          #
          # When the peer core's fabric link is reachable the ECMP lane is
          # still carried by the other core, so the gate is not urgent: be
          # lenient (3 minutes) and let this tunnel converge instead of
          # flapping. When the peer is unreachable this is the last lane and
          # a dead tunnel would black-hole flows, so fail over at the normal
          # 45s threshold.
          stale_seconds=45
          peer4=${lib.escapeShellArg (if state.healthPeer4 != null then state.healthPeer4 else "")}
          if [ -n "$peer4" ] && ${pkgs.iputils}/bin/ping -c1 -W1 "$peer4" >/dev/null 2>&1; then
            stale_seconds=180
          fi

          hs_age=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | head -1 || true)
          if [ -n "''${hs_age:-}" ] && [ "''${hs_age:-0}" -gt 0 ] && [ "''${hs_age:-9999}" -le "$stale_seconds" ]; then
            if ip link set "$lan" up 2>/dev/null; then
              echo "[wireguard-provider-health] tunnel $iface healthy (handshake ''${hs_age}s ago, stale=$stale_seconds); un-gated lan $lan" >&2
            fi
            exit 0
          fi

          # No recent handshake: fall back to the RX-delta + ICMP probe so a
          # freshly started tunnel can still prove itself before the gate.
          rx_before=$(cat "$rx_path")
          sleep 5
          rx_after=$(cat "$rx_path")

          if [ "$rx_before" = "$rx_after" ]; then
            if ! ${pkgs.iputils}/bin/ping -c1 -I "$iface" -W2 ${lib.escapeShellArg state.healthTarget4} >/dev/null 2>&1; then
              echo "[wireguard-provider-health] no RX delta and ping failed; gating $lan" >&2
              bring_lan_down
              exit 0
            fi
          fi

          # Tunnel is healthy: re-open the fabric link so the ECMP can use it.
          if ip link set "$lan" up 2>/dev/null; then
            echo "[wireguard-provider-health] tunnel $iface healthy; un-gated lan $lan" >&2
          fi
        '';
      };
    };

  healthTimer =
    state:
    {
      description = "Periodic provider tunnel health check";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = state.healthInterval;
        AccuracySec = "5s";
        Unit = "wireguard-provider-health.service";
      };
    };
}
