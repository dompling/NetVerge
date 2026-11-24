# MITM desktop review 09 revision: standalone main navigation

User requested a Surge-like dedicated MITM page, not an entry inside Settings. Replace the pending settings dialog increment before acceptance; do not keep two UI surfaces.

## Functional correctness
- Register /mitm in shared navigation metadata and existing router and sidebar; new default item between Rules and Logs, supports existing collapsed and reordered sidebar. Existing saved custom order is preserved by the existing order resolver, which appends newly available paths. Windows/macOS only, startup-page selector respects the same platform gate. No duplicate setting search result or Clash settings entry. 
- Use BasePage and responsive existing MUI cards for local engine status and CA information/actions; no modal wrapper or close button. Explicit refresh, focus refresh and route-lifetime fetch. Reuse previously implemented certificate validation and management guards; before an action fetch a fresh snapshot and reject changed fingerprint rather than relying on cached data.
- Keep actual enable/disable and hostname editing pending the local configuration stage; no fake switches. Unit tests cover unique route and platform gating in addition to certificate model tests. Generated locale and IPC checks unchanged.

## Architecture/reuse
One route and one view model. Remove the old dialog and move its model/tests to feature directory. Reuse shared navigation metadata, router, sidebar persistence, BasePage, MUI, existing generated bindings and translations. Existing locale namespace is retained to avoid unnecessary churn in this revision. No new backend API or dependency. 

## Security/stability
No trust mutation, arbitrary file input, or network routing changes. Certificate actions still use the verified public snapshot and native confirmation. Local link health and trust assessment remain distinct. Linux nav hidden until its milestone. Real UI visual inspection, desktop TUN, private ACL and full production trust mutation remain pending. No claim of completed CI until the replacement build passes. Old integration CI push is superseded by concurrency.
