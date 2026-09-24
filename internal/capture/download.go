package capture

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Download tests whether the issued URL works without the device's credentials.
// Only a complete, checksum-verified HAP is published at dst.
func Download(ctx context.Context, client *http.Client, a Artifact, dst string) error {
	if a.Availability() == "redacted" {
		return errors.New("capture has redacted URL or SHA-256; obtain an unredacted response before downloading")
	}
	if a.Kind != "original" {
		return errors.New("compressed transport artifact is not a HAP; select an original file")
	}
	expected, err := hex.DecodeString(a.SHA256)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("a valid server SHA-256 is required")
	}
	if a.Size <= 0 {
		return errors.New("a positive server file size is required")
	}
	u, err := url.Parse(a.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("artifact requires an HTTPS URL without user credentials")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
	if err != nil {
		return errors.New("invalid artifact URL")
	}
	req.Header.Set("Accept-Encoding", "identity")
	local := *client
	local.Jar = nil
	local.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 || r.URL.Scheme != "https" || r.URL.User != nil {
			return errors.New("invalid download redirect")
		}
		return nil
	}
	res, err := local.Do(req)
	if err != nil {
		return errors.New("download transport failed (signed URL omitted)")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", res.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".hap-capture-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(res.Body, a.Size+1))
	if err != nil {
		return errors.New("download body read failed")
	}
	if n != a.Size {
		return fmt.Errorf("file size mismatch: got %d, expected %d", n, a.Size)
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), a.SHA256) {
		return errors.New("SHA-256 mismatch")
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	z, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return errors.New("verified bytes are not a ZIP/HAP; no HAP was saved")
	}
	hasModule := false
	for _, f := range z.File {
		if f.Name == "module.json" {
			hasModule = true
			break
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	if !hasModule {
		return errors.New("ZIP lacks root module.json; no HAP was saved")
	}
	// Link atomically refuses to overwrite an existing output path.
	if err := os.Link(tmp.Name(), dst); err != nil {
		return err
	}
	return nil
}
