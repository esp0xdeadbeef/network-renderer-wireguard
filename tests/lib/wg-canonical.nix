# Test-side adapter: turn a model fixture into the canonical renderer input.
#
# The renderer's contract is `canonicalSites` + `canonicalWireGuard` (the
# bundle's canonical content). The existing fixtures are written against the
# producer's model shape, and `tests/` is excluded from the RR_RAW_CPM_INPUT
# scan, so the translation lives here rather than in the renderer: a fixture
# names the model once, and this file maps it to what the renderer may consume.
model:
let
  data = model.data or { };

  overlayEntries = builtins.concatMap
    (enterprise:
      let sites = data.${enterprise} or { }; in
      builtins.concatMap
        (site:
          let overlays = sites.${site}.overlays or { }; in
          map
            (overlayName:
              let overlay = overlays.${overlayName}; in
              {
                inherit enterprise site;
                overlay = overlayName;
                terminateOn = overlay.terminateOn or [ ];
                nodes = overlay.nodes or { };
                providerBootstrapDns = overlay.providerBootstrapDns or [ ];
              })
            (builtins.attrNames overlays))
        (builtins.attrNames sites))
    (builtins.attrNames data);
in
{
  canonicalSites = { overlays = overlayEntries; };
  canonicalWireGuard = {
    providers = model.wgInventory or { };
    contracts = {
      wireguard = (model.providerContracts or { }).wireguard or { };
    };
  };
}
