# wg-conf-to-secrets

Convert a raw WireGuard provider profile (`.conf`) into the field-by-field JSON
that the s88 WireGuard renderer consumes.

The renderer **never** parses or imports the raw provider file. Only the fields
below are carried forward; every other provider-injected key is dropped and
never executed.

## Why

Commercial VPN providers ship `.conf` files that may contain arbitrary
`PostUp`/`PostDown`/`PreUp`/`PreDown` scripts, `Table`, `SaveConfig`, `FwMark`,
and other fields. Importing such a file verbatim would execute provider-controlled
commands. Instead:

1. Run this tool once on the provider file to extract the required fields.
2. Encrypt the extracted fields as a SOPS secret (the endpoint is also a secret).
3. Feed those fields into the renderer's `wgInventory` (`peers`, `privateKeyFile`).

## Extracted fields

| Field               | Source line        | Secret? |
|---------------------|--------------------|---------|
| `privateKey`        | `[Interface] PrivateKey` | yes |
| `address`           | `[Interface] Address`    | yes |
| `dns`               | `[Interface] DNS`        | yes |
| `mtu`               | `[Interface] MTU`        | no  |
| `publicKey`         | `[Peer] PublicKey`       | no  |
| `endpoint`          | `[Peer] Endpoint`        | yes |
| `allowedIPs`        | `[Peer] AllowedIPs`      | no  |
| `presharedKey`      | `[Peer] PresharedKey`    | yes |
| `persistentKeepalive` | `[Peer] PersistentKeepalive` | no |

The `endpoint` is treated as a secret: it reveals which provider and which
entry server is in use.

## Usage

```sh
# from a file
nix run .#wg-conf-to-secrets -- AirVPN_Netherlands_UDP-1637-Entry3.conf

# from stdin (never echo the private key into shell history)
wg-conf-to-secrets < provider.conf > provider-fields.json

# straight into SOPS (pipe, do not print the fields)
nix run .#wg-conf-to-secrets -- provider.conf \
  | sops --input-type json --output-type yaml -e /dev/stdin > provider-fields.yaml
```

The output is JSON:

```json
{
  "privateKey": "...",
  "address": "10.x.x.2/32, fd42::2/128",
  "dns": "10.x.x.1",
  "mtu": "1420",
  "publicKey": "...",
  "endpoint": "198.51.100.x:1637",
  "allowedIPs": "0.0.0.0/0, ::/0"
}
```
