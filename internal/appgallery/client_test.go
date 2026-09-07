package appgallery

import "testing"

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
