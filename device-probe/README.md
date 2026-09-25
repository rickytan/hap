# Device authentication probe

This temporary HarmonyOS feature module reproduces the AppGallery TSMS
credential flow on a real device. It is an investigation harness, not a general
purpose downloader. It never reads AppGallery's sandbox or existing HUKS keys.

The module:

1. creates fresh P-256 attestation and unwrap keys in its own HUKS namespace;
2. requests an anonymous-attestation credential from `/tsms/v2/credentials`;
3. reconstructs the wrapped-key import blob used by `ucs-appauth` 1.0.4-310;
4. imports the returned HMAC and AES keys with `importWrappedKeyItem`;
5. signs `client.fetchHarmonyFiles` plus its millisecond timestamp; and
6. sends one authenticated Store request for `com.ss.hm.article.news`.

The probe deletes every key it creates. A successful TSMS response is kept only
in memory. Reports contain status codes and lengths, not credentials or signed
URLs. The Store response is saved inside the debug application's private files
directory so a successful response can be examined without logging it.

`prepare.cjs` creates a private build tree using an existing local HarmonyOS
debug application's signing configuration. Signing files stay in that private
tree and are never copied into this repository:

```sh
node device-probe/prepare.cjs /path/to/debug-app /private/tmp/hap-device-probe

cd /private/tmp/hap-device-probe
DEVECO_SDK_HOME=/Applications/DevEco-Studio.app/Contents/sdk \
JAVA_HOME=/Applications/DevEco-Studio.app/Contents/jbr/Contents/Home \
/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw \
  --mode module -p module=hap_probe@default -p product=default \
  -p buildMode=debug assembleHap --no-daemon
```

Install the resulting feature HAP into the same debug bundle and start
`HapProbeAbility`. The source intentionally contains no certificate, profile,
password, Huawei account token, TSMS credential, or vendor firmware artifact.

## Current result

On a VYG-AL30 running OpenHarmony 7.0.0.105, credential issuance, both wrapped
key imports, and the 32-byte HMAC all succeeded. The Store request then returned
HTTP 206 with `rtnCode=634001` (`TSMS identify verify failed.`).

The TSMS server accepts `com.huawei.hmsapp.appgallery` as the requested kit name,
but the returned access key records the helper's attested package and signing
identity. Changing the ordinary request fields to the helper identity did not
change `634001`. In a separate one-off test, changing the access-key identity to
AppGallery produced `rtnCode=633001` (`TSMS signature verify failed.`). That
mutation is not retained in this source.

This establishes that a normal separately signed helper can reproduce the
cryptography but cannot obtain AppGallery's Store identity. The next viable
device-assisted design needs an authorized AppGallery-owned interface or a
supported way to export a package after AppGallery installs it.
