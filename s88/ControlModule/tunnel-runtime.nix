{ lib, pkgs }:

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
      route-metric=${state.wanIPv4RouteMetric}

      [ipv6]
      method=${state.wanIPv6Method}
      route-metric=${state.wanIPv6RouteMetric}
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
          FORMAT=${lib.escapeShellArg state.profileFormat}
          UUID_FILE=/run/network-renderer-wireguard.uuid

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
          UUID_FILE=/run/network-renderer-wireguard.uuid
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
      description = "Check provider tunnel health from model/provider contract";
      after = [ "wireguard-provider-ready.target" ];
      requires = [ "wireguard-provider-ready.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "wireguard-provider-health" ''
          set -euo pipefail
          iface=${lib.escapeShellArg state.vpnInterface}
          rx_path="/sys/class/net/$iface/statistics/rx_bytes"

          if [ ! -d "/sys/class/net/$iface" ]; then
            echo "[wireguard-provider-health] $iface missing; restarting provider dispatcher" >&2
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          if [ ! -r "$rx_path" ]; then
            echo "[wireguard-provider-health] cannot read $rx_path; restarting provider dispatcher" >&2
            systemctl restart wireguard-provider-dispatcher.service
            exit 0
          fi

          rx_before=$(cat "$rx_path")
          sleep 5
          rx_after=$(cat "$rx_path")

          if [ "$rx_before" = "$rx_after" ]; then
            if ! ${pkgs.iputils}/bin/ping -c1 -I "$iface" -W2 ${lib.escapeShellArg state.healthTarget4} >/dev/null 2>&1; then
              echo "[wireguard-provider-health] no RX delta and ping failed; restarting provider dispatcher" >&2
              systemctl restart wireguard-provider-dispatcher.service
              exit 0
            fi
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
