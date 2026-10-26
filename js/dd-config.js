/* =============================================================================
   Datadog RUM – central configuration. EDIT VALUES HERE ONLY.

   Loaded by every page *before* the Datadog SDK scripts and read by each page's
   DD_RUM.init / DD_LOGS.init call. Plain script (not a module) so it works from
   GitHub Pages with no build step.

   applicationId / clientToken / site  - which Datadog RUM app receives the data
   version                             - release version sent as RUM `version`
                                         (bump this on each release)

   Note: a RUM client token is *public by design* (it ships to every browser that
   loads the site). It can only write RUM/Logs events for this one application.
   It is not a secret and does not need to be hidden – only kept in one place.

   Not centralised on purpose: `service` and `env` differ per area of the site
   (landing page vs. tools vs. rumresources), and the SDK <script> URL embeds the
   region (…/us1/v7/…); if you change `site`, update that URL to match.
   ========================================================================== */
window.DD_CONFIG = Object.freeze({
  applicationId: '012a1d19-38df-4e55-9412-6ceb64e72490',
  clientToken: 'pub02889030d6147b469c6736c64e609b35',
  site: 'datadoghq.com',
  version: '2.2.0'
});
