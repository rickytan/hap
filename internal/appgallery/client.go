package appgallery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	apiPath           = "/hwmarket/api/clientApi"
	clientUA          = "HiSpace##16.5.1.301##google##Pixel 8 Pro"
	clientVersion     = "16.5.1"
	clientVersionCode = "160501301"
	webUA             = "Mozilla/5.0 (Phone;OpenHarmony 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 ArkWeb/6.0.0.42 Mobile"
)

var zoneHosts = map[string]string{
	"CN": "store-drcn.hispace.dbankcloud.com",
	"RU": "store-drru.hispace.dbankcloud.ru",
}

type Client struct {
	http        *http.Client
	sessionPath string
}

type Session struct {
	Host      string    `json:"host"`
	Zone      string    `json:"zone"`
	Sign      string    `json:"sign"`
	DeviceID  string    `json:"deviceId"`
	CreatedAt time.Time `json:"createdAt"`
}

type App struct {
	AppID        string `json:"appId,omitempty"`
	Package      string `json:"package,omitempty"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	VersionCode  string `json:"versionCode,omitempty"`
	Developer    string `json:"developer,omitempty"`
	Size         string `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	DownloadURL  string `json:"downloadUrl,omitempty"`
	ArtifactType string `json:"artifactType,omitempty"`
}

func NewClient() (*Client, error) {
	dir := os.Getenv("HAPTOOL_CONFIG_DIR")
	if dir == "" {
		var err error
		dir, err = os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(dir, "haptool")
	}
	return &Client{http: &http.Client{Timeout: 45 * time.Second}, sessionPath: filepath.Join(dir, "session.json")}, nil
}
func (c *Client) HTTPClient() *http.Client { return c.http }

func randomHex(n int) (string, error) {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *Client) Login(ctx context.Context) (*Session, error) {
	device, err := randomHex(64)
	if err != nil {
		return nil, err
	}
	probe, err := c.front(ctx, "store-dre.hispace.dbankcloud.com", device, 1)
	if err != nil {
		return nil, err
	}
	zone := stringValue(probe["serviceZone"])
	host := zoneHosts[zone]
	if host == "" {
		host = "store-dra.hispace.dbankcloud.com"
		if zone == "" {
			host = "store-dre.hispace.dbankcloud.com"
		}
	}
	sign := stringValue(probe["sign"])
	if sign == "" {
		p, err := c.front(ctx, host, device, 0)
		if err != nil {
			return nil, err
		}
		sign = stringValue(p["sign"])
	}
	if sign == "" {
		return nil, errors.New("AppGallery handshake returned no sign")
	}
	s := &Session{Host: host, Zone: zone, Sign: sign, DeviceID: device, CreatedAt: time.Now()}
	if err := c.saveSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (c *Client) front(ctx context.Context, host, device string, needZone int) (map[string]any, error) {
	p := c.common(device)
	p["method"] = "client.front2"
	p["version"] = clientVersion
	p["versionCode"] = clientVersionCode
	p["packageName"] = "com.huawei.appmarket"
	p["zone"] = "1"
	p["phoneType"] = "Pixel 8 Pro"
	p["firmwareVersion"] = "16"
	p["isFirstLaunch"] = "1"
	p["oobe"] = "0"
	p["needServiceZone"] = strconv.Itoa(needZone)
	return c.post(ctx, host, p)
}

func (c *Client) session(ctx context.Context) (*Session, error) {
	s, err := c.LoadSession()
	if err == nil && time.Since(s.CreatedAt) < 24*time.Hour {
		return s, nil
	}
	return c.Login(ctx)
}
func (c *Client) LoadSession() (*Session, error) {
	b, err := os.ReadFile(c.sessionPath)
	if err != nil {
		return nil, err
	}
	var s Session
	if err = json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Host == "" || s.Sign == "" {
		return nil, errors.New("invalid session")
	}
	return &s, nil
}
func (c *Client) saveSession(s *Session) error {
	if err := os.MkdirAll(filepath.Dir(c.sessionPath), 0700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(c.sessionPath, b, 0600)
}
func (c *Client) Revoke() error {
	err := os.Remove(c.sessionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (c *Client) Search(ctx context.Context, q string, limit int) ([]App, error) {
	s, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	p := c.common(s.DeviceID)
	p["method"] = "client.getTabDetail"
	p["sign"] = s.Sign
	p["uri"] = "searchApp|" + q
	p["maxResults"] = strconv.Itoa(limit)
	p["reqPageNum"] = "1"
	p["isSupportPage"] = "1"
	r, err := c.post(ctx, s.Host, p)
	if err != nil {
		return nil, err
	}
	if stringValue(r["rtnCode"]) != "0" {
		return nil, apiError(r)
	}
	var out []App
	for _, layout := range slice(r["layoutData"]) {
		for _, item := range slice(obj(layout)["dataList"]) {
			m := obj(item)
			if x := obj(m["appInfo"]); len(x) > 0 {
				m = x
			}
			a := appFromMap(m)
			if a.AppID != "" && a.Name != "" {
				out = append(out, a)
				if len(out) >= limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func (c *Client) Info(ctx context.Context, id string) (App, error) {
	original := id
	if !strings.HasPrefix(id, "C") {
		w, err := c.WebInfo(ctx, id)
		if err != nil {
			return App{}, err
		}
		id = w.AppID
	}
	s, err := c.session(ctx)
	if err != nil {
		return App{}, err
	}
	p := c.common(s.DeviceID)
	p["method"] = "client.appDetailById"
	p["sign"] = s.Sign
	p["id"] = id
	r, err := c.post(ctx, s.Host, p)
	if err != nil {
		return App{}, err
	}
	if stringValue(r["rtnCode"]) != "0" {
		return App{}, apiError(r)
	}
	items := slice(r["detailInfo"])
	if len(items) == 0 {
		w, webErr := c.WebInfo(ctx, original)
		if webErr == nil {
			return w, nil
		}
		return App{}, errors.New("application not found")
	}
	a := appFromMap(obj(items[0]))
	if a.AppID == "" {
		a.AppID = id
	}
	a.ArtifactType = detectType(a.DownloadURL, stringValue(obj(items[0])["ctype"]))
	return a, nil
}

func (c *Client) common(device string) map[string]string {
	return map[string]string{"ver": "1.1", "locale": "zh_CN", "serviceType": "0", "ts": strconv.FormatInt(time.Now().UnixMilli(), 10), "net": "1", "brand": "google", "manufacturer": "Google", "subBrand": "0", "deviceId": device, "deviceIdType": "9"}
}

func (c *Client) post(ctx context.Context, host string, p map[string]string) (map[string]any, error) {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	v := url.Values{}
	for _, k := range keys {
		v.Set(k, p[k])
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+apiPath, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("AppGallery returned HTTP %s", res.Status)
	}
	var out map[string]any
	if err = json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) WebInfo(ctx context.Context, id string) (App, error) {
	identity, err := randomHex(32)
	if err != nil {
		return App{}, err
	}
	base := "https://web-drcn.hispace.dbankcloud.com/edge"
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/webedge/getInterfaceCode", nil)
	if err != nil {
		return App{}, err
	}
	webHeaders(get, identity, "")
	res, err := c.http.Do(get)
	if err != nil {
		return App{}, err
	}
	var token string
	err = json.NewDecoder(res.Body).Decode(&token)
	res.Body.Close()
	if err != nil {
		return App{}, err
	}
	body := fmt.Sprintf(`{"pageNum":1,"pageSize":100,"pageId":%q,"clientPackage":"com.huawei.hmsapp.appgallery","accountZone":"CN"}`, pageID(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/harmony/page-detail", strings.NewReader(body))
	if err != nil {
		return App{}, err
	}
	webHeaders(req, identity, token+"_"+strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return App{}, err
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return App{}, err
	}
	if stringValue(doc["rtnCode"]) != "0" {
		return App{}, apiError(doc)
	}
	a := findWebApp(doc)
	if a.Package == "" {
		return App{}, errors.New("HarmonyOS application not found")
	}
	a.ArtifactType = "HAP/APP (metadata only)"
	return a, nil
}
func webHeaders(r *http.Request, identity, token string) {
	r.Header.Set("User-Agent", webUA)
	r.Header.Set("Origin", "https://appgallery.huawei.com")
	r.Header.Set("Referer", "https://appgallery.huawei.com/")
	r.Header.Set("Identity-Id", identity)
	if token != "" {
		r.Header.Set("Interface-Code", token)
	}
}
func pageID(id string) string {
	if strings.Contains(id, ".") {
		return "webAgPackage|" + id
	}
	return "webAgAppDetail|" + id
}

func findWebApp(v any) App {
	switch x := v.(type) {
	case map[string]any:
		if r := obj(x["refs_app"]); len(r) > 0 {
			a := appFromMap(r)
			if a.Package != "" {
				return a
			}
		}
		for _, y := range x {
			if a := findWebApp(y); a.Package != "" {
				return a
			}
		}
	case []any:
		for _, y := range x {
			if a := findWebApp(y); a.Package != "" {
				return a
			}
		}
	}
	return App{}
}
func appFromMap(m map[string]any) App {
	return App{AppID: first(m, "appid", "appId"), Package: first(m, "package", "packageName"), Name: stringValue(m["name"]), Version: first(m, "versionName", "version"), VersionCode: stringValue(m["versionCode"]), Developer: stringValue(m["developer"]), Size: first(m, "sizeDesc", "intro"), SHA256: stringValue(m["sha256"]), DownloadURL: first(m, "url", "downurl", "downUrl")}
}
func detectType(u, ctype string) string {
	l := strings.ToLower(strings.Split(u, "?")[0])
	for _, ext := range []string{".hap", ".app", ".apk", ".zip"} {
		if strings.HasSuffix(l, ext) {
			return strings.TrimPrefix(strings.ToUpper(ext), ".")
		}
	}
	if u != "" {
		return "package (ctype " + ctype + ")"
	}
	return "metadata only"
}
func DefaultFilename(a App) string {
	base := a.Package
	if base == "" {
		base = a.AppID
	}
	ext := ".bin"
	switch a.ArtifactType {
	case "HAP":
		ext = ".hap"
	case "APP":
		ext = ".app"
	case "APK":
		ext = ".apk"
	case "ZIP":
		ext = ".zip"
	}
	return base + "-" + a.Version + ext
}
func apiError(m map[string]any) error {
	return fmt.Errorf("AppGallery error %s: %s", stringValue(m["rtnCode"]), stringValue(m["rtnDesc"]))
}
func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}
func first(m map[string]any, ks ...string) string {
	for _, k := range ks {
		if v := stringValue(m[k]); v != "" {
			return v
		}
	}
	return ""
}
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func slice(v any) []any        { s, _ := v.([]any); return s }
