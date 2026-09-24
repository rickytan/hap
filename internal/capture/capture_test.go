package capture

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReplayPreservesSignedBodyAndHeaders(t *testing.T) {
	body := "{\"ts\":123, \"device\":\"原样\"}\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	har := `{"log":{"entries":[{"request":{"method":"POST","url":"https://store-drcn.hispace.dbankcloud.com/hwmarket/harmony/client?method=client.fetchHarmonyFiles","headers":[{"name":"X-Test-TSMS","value":"secret"},{"name":"Cookie","value":"session=secret"},{"name":"Connection","value":"X-Hop"},{"name":"X-Hop","value":"remove"},{"name":"Accept-Encoding","value":"br"}],"postData":{"encoding":"base64","text":"` + encoded + `"}},"response":{"status":200,"content":{"text":"e30=","encoding":"base64"}}}]}}`
	entries, err := ReadHAR(strings.NewReader(har))
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got, _ := io.ReadAll(r.Body)
		if string(got) != body {
			t.Fatalf("signed bytes changed: %q", got)
		}
		if r.Header.Get("X-Test-TSMS") != "secret" || r.Header.Get("Cookie") != "session=secret" {
			t.Fatal("credentials were not preserved")
		}
		if r.Header.Get("X-Hop") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Fatal("transport headers were retained")
		}
		return &http.Response{StatusCode: 206, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"rtnCode":630102}`))}, nil
	})}
	response, status, err := e.Replay(context.Background(), client)
	if err != nil || status != 206 || !bytes.Contains(response, []byte("630102")) {
		t.Fatalf("response=%s status=%d err=%v", response, status, err)
	}
	summary, _ := json.Marshal(e.Summary(0))
	if bytes.Contains(summary, []byte("secret")) {
		t.Fatal("summary disclosed credential")
	}
	b, err := e.ResponseBody()
	if err != nil || string(b) != "{}" {
		t.Fatalf("base64 response: %q %v", b, err)
	}
}

func TestRedactedDeviceResponseCannotStartDownload(t *testing.T) {
	// Minimized from the successful 2026-09-25 device response. No account,
	// application identity, key material or signed URL is retained.
	body := []byte(`{"rtnCode":0,"harmonyApps":[{"pkgName":"example.app","encType":3,"hapFiles":[{"packageUrl":"*","sha256":"*","fileSize":8232884,"compressInfo":{"downloadUrl":"*","sha256":"*","fileSize":4713909,"compressType":2}}]}]}`)
	artifacts, err := Artifacts(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[0].EncryptionType != 3 || artifacts[1].CompressionType != 2 {
		t.Fatalf("lost transport metadata: %+v", artifacts)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("redacted artifact attempted network access")
		return nil, nil
	})}
	for _, a := range artifacts {
		if a.Availability() != "redacted" {
			t.Fatal("redaction not reported")
		}
		err := Download(context.Background(), client, a, filepath.Join(t.TempDir(), "app.hap"))
		if err == nil || !strings.Contains(err.Error(), "redacted") {
			t.Fatalf("expected precise redaction error, got %v", err)
		}
	}
}

func TestAuthenticationSummaryDoesNotDiscloseValues(t *testing.T) {
	var e Entry
	e.Request.URL = "https://store-drcn.hispace.dbankcloud.com/hwmarket/harmony/client?method=client.fetchHarmonyFiles&ts=1729382400000"
	e.Request.Headers = []Header{
		{Name: "X-Msg-Ak", Value: "private-access-key"},
		{Name: "x-msg-signature", Value: "***"},
		{Name: "X-Authorization", Value: ""},
	}
	a := e.Authentication()
	if a["x-msg-ak"] != "present" || a["x-msg-signature"] != "redacted" || a["x-authorization"] != "empty" || a["timestamp"] != "present" {
		t.Fatalf("unexpected completeness report: %v", a)
	}
	b, _ := json.Marshal(e.Summary(0))
	if bytes.Contains(b, []byte("private-access-key")) || bytes.Contains(b, []byte("1729382400000")) {
		t.Fatal("summary disclosed authentication data")
	}
	e.Request.Headers = append(e.Request.Headers, Header{Name: "x-MSG-ak", Value: "second-key"})
	e.Request.URL += "&ts=1729382400001"
	a = e.Authentication()
	if a["x-msg-ak"] != "multiple" || a["timestamp"] != "invalid" {
		t.Fatal("ambiguous authentication fields were reported as complete")
	}
	e.Request.Headers = nil
	e.Request.URL = "https://example.test/"
	a = e.Authentication()
	if a["x-msg-ak"] != "missing" || a["x-msg-signature"] != "missing" || a["timestamp"] != "missing" {
		t.Fatal("absent authentication fields were reported as present")
	}
}

func TestReplayRejectsUnrelatedAndIncompleteRequests(t *testing.T) {
	for _, raw := range []string{
		`{"request":{"method":"POST","url":"https://store-drcn.hispace.dbankcloud.com.evil.test/hwmarket/harmony/client?method=client.fetchHarmonyFiles"}}`,
		`{"request":{"method":"POST","url":"https://store-drcn.hispace.dbankcloud.com/hwmarket/harmony/client?method=client.purchase"}}`,
		`{"request":{"method":"POST","url":"https://store-drcn.hispace.dbankcloud.com/hwmarket/harmony/client?method=client.fetchHarmonyFiles","postData":{"params":[]}}}`,
	} {
		var e Entry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network request"); return nil, nil })}
		if _, _, err := e.Replay(context.Background(), client); err == nil {
			t.Fatal("accepted invalid replay")
		}
	}
}

func TestArtifactsKeepModulesAndCompressedVariantsSeparate(t *testing.T) {
	body := []byte(`{"rtnCode":"0","harmonyApps":[{"pkgName":"example.app","versionName":"1","hapFiles":[{"downloadUrl":"https://cdn.test/entry","packageUrl":"https://cdn.test/entry","fileSize":123,"sha256":"original","compressInfo":{"downloadUrl":"https://cdn.test/compressed","fileSize":90,"sha256":"compressed"}},{"downloadUrl":"https://cdn.test/feature","fileSize":45,"sha256":"feature"}]}]}`)
	a, err := Artifacts(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 3 || a[0].Kind != "original" || a[1].Kind != "compressed" || a[1].SHA256 != "compressed" || a[2].Size != 45 {
		t.Fatalf("bad artifacts: %+v", a)
	}
	if _, err := Artifacts([]byte(`{"rtnCode":630102}`)); err == nil {
		t.Fatal("accepted TSMS error")
	}
}

func TestDownloadVerifiesArtifactAndPreservesExistingFile(t *testing.T) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	f, _ := z.Create("module.json")
	f.Write([]byte(`{"module":{"name":"entry"}}`))
	z.Close()
	body := buf.Bytes()
	digest := sha256.Sum256(body)
	a := Artifact{URL: "https://cdn.test/app.hap?token=private", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body)), Kind: "original"}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("download inherited credentials")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
	dst := filepath.Join(t.TempDir(), "app.hap")
	if err := Download(context.Background(), client, a, dst); err != nil {
		t.Fatal(err)
	}
	if err := Download(context.Background(), client, a, dst); err == nil {
		t.Fatal("overwrote existing HAP")
	}
	for _, change := range []func(*Artifact){
		func(a *Artifact) { a.SHA256 = strings.Repeat("0", 64) },
		func(a *Artifact) { a.Size++ },
		func(a *Artifact) { a.Kind = "compressed" },
	} {
		bad := a
		change(&bad)
		output := filepath.Join(t.TempDir(), "bad.hap")
		if err := Download(context.Background(), client, bad, output); err == nil {
			t.Fatal("accepted invalid artifact")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("left invalid output")
		}
	}
	// A correct digest of HTML must not be mistaken for a HAP.
	body = []byte("<html>expired URL</html>")
	digest = sha256.Sum256(body)
	a.SHA256 = hex.EncodeToString(digest[:])
	a.Size = int64(len(body))
	if err := Download(context.Background(), client, a, filepath.Join(t.TempDir(), "html.hap")); err == nil {
		t.Fatal("accepted HTML as HAP")
	}
}
