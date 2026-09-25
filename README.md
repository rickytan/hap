# haptool

> **Status: Work in progress (WIP).** Native HarmonyOS package downloads still
> require a device-authenticated AppGallery request flow.

Experimental command-line client for Huawei AppGallery. It can establish an
AppGallery client session, search the catalogue, inspect native HarmonyOS app
metadata, and download a package when AppGallery returns a package URL.

```sh
go build -o haptool .
./haptool web-check com.ss.hm.article.news
./haptool auth login
./haptool search 今日头条
./haptool info com.ss.hm.article.news
./haptool fetch com.ss.hm.article.news --json
./haptool download com.ss.hm.article.news -output 今日头条.hap
```

`auth login` currently creates the same anonymous device session used by the
AppGallery client catalogue API. The public web login does not expose a Huawei
ID token that can safely be reused by a CLI, so paid-app entitlement and account
purchases are not implemented.

The AppGallery web page shows an install button for a HarmonyOS user agent, but
the button opens `store://appgallery.huawei.com/...`; it does not contain a
browser-downloadable HAP URL. Native app metadata is available from the web
detail API. Actual package URLs are device/session dependent and may be withheld
for native HarmonyOS apps.

`fetch` calls the native HarmonyOS AppGallery endpoint
`/hwmarket/harmony/client?method=client.fetchHarmonyFiles`. A desktop request
can be tuned with the device fields visible in AppGallery logs:

```sh
HAPTOOL_HARMONY_MODEL=VYG-AL30 \
HAPTOOL_HARMONY_PHONE_TYPE=VYG-AL30 \
HAPTOOL_HARMONY_CLIENT_CAPABILITY=111111111111110100111101110111 \
HAPTOOL_HARMONY_GL_VERSION=Maleoon.V300.3167dda101f4e9e02055e9301d568b3329f77cc1 \
./haptool fetch com.ss.hm.article.news --json
```

This still returns `x-error-code=630102` / `TSMS verify parameters blank.` on a
desktop client. The ordinary model, capability, GPU, and version fields are not
sufficient. A live AppGallery-owned request now proves that the endpoint returns
the package metadata and downloads successfully on the phone, but its URL,
hash, and transfer key are redacted from logs.

Static analysis of AppGallery 5.3.2.300 traced TSMS signing to the bundled
`ucs-appauth` SDK: HMAC-SHA256 over API method plus timestamp, using a HUKS-managed
key obtained through anonymous attestation. A real-device probe has now validated
credential issuance, wrapped SK/DK import and Store-request signing against the
current TSMS service. The independently signed helper still fails Store identity
verification because the issued credential is bound to the helper's attested
package and signing identity. It also cannot connect to AppGallery's observed
download service: HarmonyOS rejects the hidden service as an invisible
component. See the investigation notes and
[`device-probe`](device-probe/README.md).

The public AppGallery Kit surface does not expose raw packages. Its product-view
API opens an AppGallery detail page, its update API checks the calling signed
application, and its module-install API installs on-demand modules rather than
exporting another application's HAP. Links and the device evidence are recorded
in the investigation notes.

AppGallery Connect's "request download link" API is also not a package-export
API. It is an authenticated media-promotion service that returns a temporary
`hiapplink://com.huawei.appmarket?...` link. Opening that link delegates the
download and installation to AppGallery; it does not return a `.hap` URL or
bytes to the caller. The account must have an approved media app and matching
API-client credentials before the endpoint can be used.

### Device capture experiments

Export a HAR with decrypted HTTPS request and response bodies from an authorized
AppGallery session. Keep captures outside the repository: they can contain
account credentials and signed download URLs. HAR files and `/captures/` are
ignored by Git.

```sh
# Lists only Harmony API requests; credentials and signed URLs are omitted.
./haptool capture inspect /private/tmp/appgallery.har

# Use the entry number printed above; these numbers are examples.
./haptool capture files /private/tmp/appgallery.har --entry 12
./haptool capture download /private/tmp/appgallery.har --entry 12 --file 0 -o entry.hap

# Preserve captured request body bytes and application headers, without
# refreshing timestamps/signatures or following redirects.
./haptool capture replay /private/tmp/appgallery.har --entry 12 -o /private/tmp/replayed.json
./haptool capture files /private/tmp/replayed.json --response
```

`capture download` first tests the signed URL without device cookies or account
headers. It requires matching server-provided size and SHA-256, a ZIP archive,
and a root `module.json`; existing output files are never overwritten. This is
an integrity/structure check, not a Huawei signature or installation check.
Each module and compressed alternative is listed separately. Compressed
transport files are not treated as HAPs; download an `original` entry.

`capture replay` supports only `client.fetchHarmonyFiles` and
`client.getPageDetail`. It saves the response with mode `0600`, including error
responses, for comparison. Transport headers are reconstructed by Go, so replay
preserves application-level data but does not reproduce the device's TLS or
HTTP/2 fingerprint. Expired, redacted or incomplete captures cannot establish
whether TSMS is hardware-bound. No authenticated HAP download has been verified
yet.

`capture inspect` also reports whether `x-msg-ak`, `x-msg-signature`,
`X-Authorization` and the query timestamp are present, missing or malformed
(including recognized redactions). Presence is not proof that authentication
is valid. No credential values are printed.

The [device investigation notes](docs/device-download-investigation.md) record
the successful phone-side install and the remaining barriers to a CLI download.
`capture files` reports redacted values and transport types. The normal
`download` command also refuses compressed-only responses and validates an
original HAP before saving it; apps with multiple HAP modules require further
implementation.

This project uses undocumented consumer AppGallery endpoints. They can change
without notice. Download only applications you are entitled to use and observe
the applicable AppGallery terms and local law.
