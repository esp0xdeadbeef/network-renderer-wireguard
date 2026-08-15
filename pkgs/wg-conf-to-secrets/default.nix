{ pkgs }:

pkgs.writeShellApplication {
  name = "wg-conf-to-secrets";
  runtimeInputs = [
    pkgs.gawk
    pkgs.jq
  ];
  text = ''
    set -euo pipefail

    # wg-conf-to-secrets — convert a raw WireGuard provider profile (.conf)
    # into the field-by-field JSON the s88 WireGuard renderer consumes.
    #
    # The renderer never parses or imports the raw provider file. Only the
    # fields below are carried forward; every other provider-injected key
    # (PostUp, PostDown, PreUp, PreDown, Table, SaveConfig, FwMark, arbitrary
    # scripts, ...) is dropped and never executed.
    #
    # Usage:
    #   wg-conf-to-secrets <provider.conf >secrets.json
    #   wg-conf-to-secrets provider.conf | sops ... -e > secrets.yaml

    conf="''${1:--}"

    ${pkgs.gawk}/bin/awk '
      {
        line = $0
        if (line ~ /^[[:space:]]*[A-Za-z]+[[:space:]]*=/) {
          pos = index(line, "=")
          key = substr(line, 1, pos - 1)
          val = substr(line, pos + 1)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
          printf "%s\t%s\n", key, val
        }
      }
    ' "$conf" \
      | ${pkgs.jq}/bin/jq -Rn '
          reduce inputs as $line ({};
            ($line | split("\t")) as $kv
            | . + { ($kv[0]): $kv[1] })
        '
  '';
}
