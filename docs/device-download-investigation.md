# Device download investigation

Status: WIP. The CLI has not downloaded an authenticated AppGallery HAP.

The rebuilt desktop CLI was retested on 2026-09-25 with
`haptool fetch com.ss.hm.article.news --json`. It still returned HTTP 206,
`x-error-code=630102`, and `TSMS verify parameters blank.`. All Go tests passed;
that does not establish an end-to-end authenticated download.

## Verified on 2026-09-25

The connected phone reports `OpenHarmony-7.0.0.105`. A fresh AppGallery install
of the free utility 简约计算器 (`com.zb.mh.newcomjisuanqihmmh`, version `1.0.0`)
completed, and its detail page changed from 安装 to 打开. The application was
left installed; it was not launched.

Live AppGallery-domain logs show `AppGalleryService` requesting
`client.fetchHarmonyFiles` and receiving `rtnCode: 0` with one entry module:

| Field | Observed value |
| --- | --- |
| Original file size | 8,232,884 bytes |
| Transfer file size | 4,713,909 bytes |
| fileType | 4 |
| compressType | 2 |
| encType | 3 |
| packageUrl, compressed downloadUrl, SHA-256 | `*` |
| encryptedTransferKey, transferKeyHash | `*` |

These numeric type values are recorded without assuming their undocumented
algorithm meanings. The response also contains `metaData` and `protectMetaData`.
No usable URL appeared elsewhere in the captured AppGallery download logs.
The system Request service diagnostic (`hidumper -s 3706 -a -t`) showed zero
tasks when checked after completion; it did not provide a download address.

## Earlier certificate experiment in this session

NetCap's public CA certificate matched the enabled user CA in Settings by
SHA-256 fingerprint and serial number. With HTTPS interception enabled,
AppGallery connections failed with `ssl/tls alert certificate unknown` and
its detail page failed to load. Disabling HTTPS interception restored loading.
This rules out a stale installed CA for that experiment. It does not distinguish
certificate pinning from exclusion of user-installed roots or another trust
policy. No system trust settings were weakened.

## Implications for the CLI

The raw logs cannot serve as a replayable HAR: application authentication
headers are missing and response values are deliberately redacted. Changing
the user agent or guessing the hidden URLs does not address that gap.

The download code now keeps original HAPs separate from transport variants,
reports redacted captures explicitly, and verifies size, SHA-256 and ZIP/HAP
structure before saving an original file. These checks do not verify Huawei
signatures or establish that an encrypted package is installable elsewhere.

## Offline signing analysis

An official [firmware archive](https://update.dbankcdn.com/download/data/pub_13/HWHOTA_hota_900_9/24/v3/fThYWevRQueNuU8HO4XqWw/full/update_full_base.zip)
was accessible on 2026-09-25. Its `update.bin` component table was parsed using
the format in OpenHarmony's [update_packaging_tools](https://github.com/openharmony/update_packaging_tools).
The ZIP's deflated stream was read until the system component was complete;
2,444,230,656 network bytes were consumed rather than downloading the entire ZIP.
The 4,114,612,224-byte EROFS system image matched its component-table SHA-256.
This is a content-integrity check, not independent firmware-signature validation.

The extracted AppGallery is **5.3.2.300**, version code `1450302300`, from an older
firmware linked in the 2024 investigation below. It is not the current phone's
AppGallery. `ServerRequestKit.hsp/ets/modules.abc` contains
`@hms-security/ucs-appauth` **1.0.4-310**. DevEco's `ark_disasm` successfully
disassembled it locally, without executing firmware code.

| Artifact | SHA-256 |
| --- | --- |
| system image | `d49ce02a069fcf30af9c968bba7b24721497b486a770bfd375ad9597ccb4ce2f` |
| ServerRequestKit.hsp | `a6522ef2b09e8bb74102c1d43bd2af45818039754bc9099806c46b72d3960541` |
| ServerRequestKit modules.abc | `f9bd08a1b3fb93c3f8c70de1ef24c8323cfbaa6e418aa837cc745eb3cd913778` |

The following findings come from method bodies, not just string matches:

| Method | Observed behavior in this version |
| --- | --- |
| `ServerRequest.constructParam` | Forms signing input by concatenating API method and decimal `Date.getTime()` timestamp, without a separator. Serializes the body separately. |
| `ServerRequest.formatHeader` | Adds `x-msg-signature`, `x-msg-ak` when nonempty; serializes a separate authorization object into `X-Authorization`. |
| `StoreUcsTokenManager.applyUcsToken` | UTF-8 encodes signing input, requests `HMAC_SHA256`, Base64 encodes the returned signature, and uses the returned AK. |
| `CredentialSigner.initSigner` / `HuksSigner.sign` | Require the `SK` key alias and execute a HUKS HMAC session. |
| `CredentialReqGenerator.preBuild` / `buildHeader` / `buildPayload` | Build a credential request with anonymous attestation, an unwrap public key, application ID and service/package name. |
| `HuksKeyManager.huksAnonAttest` | Calls `anonAttestKeyItem` (or its user-specific variant); `getAnonAttestation` expects a three-certificate chain. |
| `CredentialRespHandler.process` / `HuksKeyManager.importWrappedKey` | Import returned wrapped key material through HUKS. |
| `CredentialEntity` parsing | Checks the credential's package name and certificate fingerprint against the running application. |

The SDK uses `/tsms/v2/credentials` for credential issuance. The observed signing
input can be summarized as `UTF8(method + decimal_timestamp_ms)`; knowing this
format and the HMAC algorithm does not supply a usable secret key. We have not
confirmed the current server's freshness window, replay behavior, or whether
the current AppGallery retains this exact format. The old bytecode does not by
itself prove the properties of every supported HUKS backend or rule out all
desktop implementations.

On the current phone, listing
`/data/app/el2/100/base/com.huawei.hmsapp.appgallery` returned `Permission denied`.
A separately signed helper application cannot simply be assumed to have access
to AppGallery's credentials or key aliases. No such access has been demonstrated.

For reproducing the static inspection after obtaining that system image:

```sh
# dump.erofs is provided by erofs-utils; keep vendor artifacts outside this repo.
dump.erofs --cat --path=/system/app/AppGallery/ServerRequestKit.hsp system.img > /private/tmp/ServerRequestKit.hsp
unzip -p /private/tmp/ServerRequestKit.hsp ets/modules.abc > /private/tmp/ServerRequestKit.abc
ark_disasm /private/tmp/ServerRequestKit.abc /private/tmp/ServerRequestKit.pa
rg -n 'constructParam|applyUcsToken|CredentialSigner|huksAnonAttest|importWrappedKey' /private/tmp/ServerRequestKit.pa
```

## Remaining investigation

An unredacted, authorized client request/response is still needed to test URL
portability and request replay. Offline analysis has now identified the older
TSMS credential/signing chain. The next protocol milestone is validating that
chain against current AppGallery and finding an authorized way to invoke its
signer or obtain a complete request. A desktop HMAC implementation alone would
not meet that milestone. Transfer decoding and code protection remain separate
work even after request authentication succeeds.

A first-hand [2024 protocol investigation](https://wuxianlin.com/2024/10/19/harmonyos-next-code-protect/)
describes separate code-protection requests (`getCloudChallenge`,
`getNegotiationKey`) and an HMS `security.codeProtect` service. This is a lead
for offline analysis, not evidence that the current TSMS authentication uses
the same mechanism. Account login, request authentication, transfer decoding
and application code protection must be investigated separately.

Raw device logs, responses, vendor packages, firmware images and disassembly
are kept outside the repository. Tests use a minimal synthetic fixture with the
observed redaction and transport fields. `capture inspect` reports presence of
the three observed authentication headers and a millisecond timestamp, without
printing values or claiming their validity.
