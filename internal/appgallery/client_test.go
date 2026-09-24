package appgallery

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHarmonyDownloadURLDoesNotSelectTransportOrRedactedFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		file HarmonyFile
		want string
	}{
		{"prefer original", HarmonyFile{PackageURL: "https://cdn.example/entry.hap", Compress: &HarmonyCompress{DownloadURL: "https://cdn.example/transport"}}, "https://cdn.example/entry.hap"},
		{"compressed only", HarmonyFile{Compress: &HarmonyCompress{DownloadURL: "https://cdn.example/transport"}}, ""},
		{"redacted", HarmonyFile{PackageURL: "*", SHA256: "*"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := HarmonyApp{HapFiles: []HarmonyFile{tc.file}}
			if got := a.DownloadURL(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindWebApp(t *testing.T) {
	doc := map[string]any{"pages": []any{map[string]any{"data": map[string]any{
		"refs_app": map[string]any{
			"appId":       "C1",
			"packageName": "com.example.app",
			"name":        "Example",
			"version":     "1.2.3",
		},
	}}}}
	a := findWebApp(doc)
	if a.AppID != "C1" || a.Package != "com.example.app" || a.Version != "1.2.3" {
		t.Fatalf("findWebApp() = %#v", a)
	}
}

func TestDetectType(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://example.test/a.hap?sign=x", "HAP"},
		{"https://example.test/a.app", "APP"},
		{"https://example.test/a.apk", "APK"},
		{"", "metadata only"},
	} {
		if got := detectType(tc.url, "17"); got != tc.want {
			t.Errorf("detectType(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestHTTPStatusErrorIncludesHarmonyDetails(t *testing.T) {
	res := &http.Response{
		Status:     "206 Partial Content",
		StatusCode: 206,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"rtnCode":"630102","rtnDesc":"TSMS verify parameters blank."}`)),
	}
	res.Header.Set("x-error-code", "630102")

	got := httpStatusError("Harmony API", res).Error()
	for _, want := range []string{
		"HTTP 206 Partial Content",
		"x-error-code=630102",
		"rtnCode=630102",
		"TSMS verify parameters blank.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("httpStatusError() = %q, want to contain %q", got, want)
		}
	}
}
