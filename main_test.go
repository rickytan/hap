package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFlagsFirst(t *testing.T) {
	got := flagsFirst([]string{"今日头条", "--limit", "5", "--json"}, map[string]bool{"--limit": true})
	want := []string{"--limit", "5", "--json", "今日头条"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flagsFirst() = %#v, want %#v", got, want)
	}
}

func TestDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("package bytes"))
	}))
	defer server.Close()

	dst := filepath.Join(t.TempDir(), "app.hap")
	if err := download(context.Background(), server.Client(), server.URL, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "package bytes" {
		t.Fatalf("downloaded %q", got)
	}
}
