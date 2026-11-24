# Test-side adapter: turn a model fixture into the canonical renderer input.
#
# The renderer's contract is `canonicalSites` + `canonicalOverlays` (the
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
  # One record per overlay, provider as a field. The fixture used to hand the
  # renderer a provider-named collection; that is the shape this test is meant to
  # stop existing, so it now builds what the producer publishes.
  canonicalOverlays = {
    byOverlay = builtins.listToAttrs (
      map
        (entry: {
          name = entry.overlay;
          value = {
            provider = entry.provider or "wireguard";
            providerInterface = (model.wgInventory or { }).${entry.overlay}.interface or null;
            providerMaterial = (model.wgInventory or { }).${entry.overlay} or { };
            providerContract = (model.providerContracts or { }).wireguard.${entry.overlay} or null;
            inherit (entry) terminateOn nodes providerBootstrapDns;
          };
        })
        overlayEntries
    );
    overlays = overlayEntries;
  };
}
