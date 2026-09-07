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

This project uses undocumented consumer AppGallery endpoints. They can change
without notice. Download only applications you are entitled to use and observe
the applicable AppGallery terms and local law.
