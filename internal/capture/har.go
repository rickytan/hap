// Package capture supports experiments with device-authenticated AppGallery
// requests. It never synthesizes or refreshes authentication material.
package capture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const MaxCaptureBytes = 64 << 20

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Entry struct {
	Request struct {
		Method   string   `json:"method"`
		URL      string   `json:"url"`
		Headers  []Header `json:"headers"`
		PostData *struct {
			Text     *string `json:"text"`
			Encoding string  `json:"encoding"`
			MimeType string  `json:"mimeType"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

func ReadHAR(r io.Reader) ([]Entry, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxCaptureBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCaptureBytes {
		return nil, errors.New("HAR exceeds 64 MiB limit")
	}
	var h struct {
		Log *struct {
			Entries []Entry `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, errors.New("invalid HAR JSON")
	}
	if h.Log == nil {
		return nil, errors.New("HAR is missing log")
	}
	return h.Log.Entries, nil
}

func (e Entry) Harmony() bool {
	u, err := url.Parse(e.Request.URL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return u.Scheme == "https" && u.User == nil && (u.Port() == "" || u.Port() == "443") &&
		(strings.HasSuffix(host, ".hispace.dbankcloud.com") || strings.HasSuffix(host, ".hispace.dbankcloud.ru")) &&
		u.Path == "/hwmarket/harmony/client"
}

// Summary deliberately omits query values, cookies, body and credential values.
func (e Entry) Summary(index int) map[string]any {
	u, _ := url.Parse(e.Request.URL)
	names := make([]string, 0, len(e.Request.Headers))
	for _, h := range e.Request.Headers {
		names = append(names, h.Name)
	}
	method := ""
	if u != nil {
		method = u.Query().Get("method")
	}
	return map[string]any{"entry": index, "method": method, "status": e.Response.Status,
		"headerNames": names, "hasRequestBody": e.Request.PostData != nil && e.Request.PostData.Text != nil,
		"responseBytes": len(e.Response.Content.Text), "authentication": e.Authentication()}
}

// Authentication reports capture completeness, not credential validity. These
// header names were traced in AppGallery 5.3.2.300; newer clients may differ.
func (e Entry) Authentication() map[string]string {
	result := map[string]string{}
	for _, name := range []string{"x-msg-ak", "x-msg-signature", "x-authorization"} {
		state := "missing"
		count := 0
		for _, h := range e.Request.Headers {
			if !strings.EqualFold(h.Name, name) {
				continue
			}
			count++
			value := strings.TrimSpace(h.Value)
			switch {
			case value == "":
				state = "empty"
			case strings.Contains(value, "*") || strings.EqualFold(value, "[redacted]"):
				state = "redacted"
			default:
				state = "present"
			}
		}
		if count > 1 {
			state = "multiple"
		}
		result[name] = state
	}
	result["timestamp"] = "missing"
	if u, err := url.Parse(e.Request.URL); err == nil {
		if values, ok := u.Query()["ts"]; ok {
			result["timestamp"] = "invalid"
			if len(values) == 1 && len(values[0]) == 13 && strings.IndexFunc(values[0], func(r rune) bool { return r < '0' || r > '9' }) == -1 {
				result["timestamp"] = "present"
			}
		}
	}
	return result
}

func decode(s, encoding string) ([]byte, error) {
	switch encoding {
	case "":
		return []byte(s), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("invalid base64 capture body")
		}
		return b, nil
	default:
		return nil, errors.New("unsupported capture body encoding")
	}
}

func (e Entry) ResponseBody() ([]byte, error) {
	return decode(e.Response.Content.Text, e.Response.Content.Encoding)
}

func (e Entry) Replay(ctx context.Context, client *http.Client) ([]byte, int, error) {
	if !e.Harmony() {
		return nil, 0, errors.New("replay requires a Huawei Harmony endpoint")
	}
	u, _ := url.Parse(e.Request.URL)
	method := u.Query().Get("method")
	if e.Request.Method != "POST" || (method != "client.fetchHarmonyFiles" && method != "client.getPageDetail") {
		return nil, 0, errors.New("replay supports only POST fetchHarmonyFiles/getPageDetail")
	}
	if e.Request.PostData == nil || e.Request.PostData.Text == nil {
		return nil, 0, errors.New("HAR lacks original request body; cannot reproduce signed bytes")
	}
	body, err := decode(*e.Request.PostData.Text, e.Request.PostData.Encoding)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.Request.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("invalid replay request")
	}
	// Remove transport headers, including headers named by Connection. All
	// application authentication headers and the body remain unchanged.
	skip := map[string]bool{"host": true, "content-length": true, "connection": true, "transfer-encoding": true,
		"accept-encoding": true, "keep-alive": true, "proxy-authorization": true, "proxy-authenticate": true, "te": true, "trailer": true, "upgrade": true}
	for _, h := range e.Request.Headers {
		if strings.EqualFold(h.Name, "Connection") {
			for _, name := range strings.Split(h.Value, ",") {
				skip[strings.ToLower(strings.TrimSpace(name))] = true
			}
		}
	}
	for _, h := range e.Request.Headers {
		if !skip[strings.ToLower(h.Name)] && !strings.HasPrefix(h.Name, ":") {
			req.Header.Add(h.Name, h.Value)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", e.Request.PostData.MimeType)
	}
	local := *client
	local.Jar = nil // Do not combine a different session with captured credentials.
	local.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := local.Do(req)
	if err != nil {
		return nil, 0, errors.New("replay transport failed (URL and credentials omitted)")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxCaptureBytes+1))
	if err != nil {
		return nil, res.StatusCode, errors.New("cannot read replay response")
	}
	if len(b) > MaxCaptureBytes {
		return nil, res.StatusCode, errors.New("replay response exceeds 64 MiB limit")
	}
	return b, res.StatusCode, nil
}

type Artifact struct {
	Package         string `json:"package"`
	Version         string `json:"version"`
	URL             string `json:"-"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	Kind            string `json:"kind"`
	EncryptionType  int    `json:"encType"`
	CompressionType int    `json:"compressType,omitempty"`
}

// Availability describes captured metadata without exposing the signed URL.
func (a Artifact) Availability() string {
	if strings.Contains(a.URL, "*") || strings.Contains(a.SHA256, "*") {
		return "redacted"
	}
	if a.Kind == "compressed" {
		return "transport-only"
	}
	return "requires-validation"
}

func CheckResponse(body []byte) error {
	var r struct {
		Code json.Number `json:"rtnCode"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return errors.New("invalid Harmony response JSON")
	}
	if r.Code == "" {
		return errors.New("Harmony response lacks rtnCode")
	}
	if r.Code != "0" {
		return fmt.Errorf("Harmony response rtnCode=%s", r.Code)
	}
	return nil
}

// Artifacts returns each server-issued file separately. Compressed alternatives
// are not substituted for HAPs, and multi-module apps are not collapsed.
func Artifacts(body []byte) ([]Artifact, error) {
	var r struct {
		Code json.Number `json:"rtnCode"`
		Apps []struct {
			EncryptionType int    `json:"encType"`
			Package        string `json:"pkgName"`
			Bundle         string `json:"bundleName"`
			PackageName    string `json:"packageName"`
			Version        string `json:"versionName"`
			Files          []struct {
				URL        string `json:"downloadUrl"`
				PackageURL string `json:"packageUrl"`
				SHA256     string `json:"sha256"`
				Size       int64  `json:"fileSize"`
				Compress   *struct {
					Type   int    `json:"compressType"`
					URL    string `json:"downloadUrl"`
					SHA256 string `json:"sha256"`
					Size   int64  `json:"fileSize"`
				} `json:"compressInfo"`
			} `json:"hapFiles"`
		} `json:"harmonyApps"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errors.New("response is not a supported Harmony JSON response")
	}
	if r.Code != "0" {
		return nil, fmt.Errorf("Harmony response rtnCode=%s", r.Code)
	}
	var out []Artifact
	for _, a := range r.Apps {
		pkg := a.Package
		if pkg == "" {
			pkg = a.Bundle
		}
		if pkg == "" {
			pkg = a.PackageName
		}
		for _, f := range a.Files {
			seen := map[string]bool{}
			for _, u := range []string{f.URL, f.PackageURL} {
				if u != "" && !seen[u] {
					out = append(out, Artifact{Package: pkg, Version: a.Version, URL: u, SHA256: f.SHA256, Size: f.Size, Kind: "original", EncryptionType: a.EncryptionType})
					seen[u] = true
				}
			}
			if c := f.Compress; c != nil && c.URL != "" {
				out = append(out, Artifact{Package: pkg, Version: a.Version, URL: c.URL, SHA256: c.SHA256, Size: c.Size, Kind: "compressed", EncryptionType: a.EncryptionType, CompressionType: c.Type})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("response contains no downloadable Harmony files")
	}
	return out, nil
}
