package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rickytan/haptool/internal/appgallery"
	"github.com/rickytan/haptool/internal/capture"
)

const version = "0.1.0"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return flag.ErrHelp
	}
	if args[0] == "capture" {
		return captureCommand(ctx, args[1:], stdout, stderr)
	}
	client, err := appgallery.NewClient()
	if err != nil {
		return err
	}
	switch args[0] {
	case "auth":
		return authCommand(ctx, client, args[1:], stdout)
	case "search":
		fs := flag.NewFlagSet("search", flag.ContinueOnError)
		var limit int
		var jsonOut bool
		fs.IntVar(&limit, "limit", 10, "maximum results")
		fs.IntVar(&limit, "l", 10, "maximum results")
		fs.BoolVar(&jsonOut, "json", false, "print JSON")
		if err := fs.Parse(flagsFirst(args[1:], map[string]bool{"--limit": true, "-limit": true, "-l": true})); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New("usage: haptool search <term> [--limit N]")
		}
		items, err := client.Search(ctx, strings.Join(fs.Args(), " "), limit)
		if err != nil {
			return err
		}
		if jsonOut {
			return writeJSON(stdout, items)
		}
		for _, a := range items {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", a.AppID, a.Package, a.Version, a.Name)
		}
		return nil
	case "info":
		fs := flag.NewFlagSet("info", flag.ContinueOnError)
		var id string
		var jsonOut bool
		fs.StringVar(&id, "id", "", "AppGallery C identifier or bundle name")
		fs.BoolVar(&jsonOut, "json", false, "print JSON")
		if err := fs.Parse(flagsFirst(args[1:], map[string]bool{"--id": true, "-id": true})); err != nil {
			return err
		}
		if id == "" && fs.NArg() > 0 {
			id = fs.Arg(0)
		}
		if id == "" {
			return errors.New("usage: haptool info <app-id-or-bundle>")
		}
		a, err := client.Info(ctx, id)
		if err != nil {
			return err
		}
		if jsonOut {
			return writeJSON(stdout, a)
		}
		fmt.Fprintf(stdout, "Name: %s\nBundle: %s\nApp ID: %s\nVersion: %s (%s)\nDeveloper: %s\nSize: %s\nArtifact: %s\n", a.Name, a.Package, a.AppID, a.Version, a.VersionCode, a.Developer, a.Size, a.ArtifactType)
		return nil
	case "fetch":
		fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
		var id string
		var jsonOut bool
		fs.StringVar(&id, "id", "", "package name or AppGallery C identifier")
		fs.BoolVar(&jsonOut, "json", false, "print JSON")
		if err := fs.Parse(flagsFirst(args[1:], map[string]bool{"--id": true, "-id": true})); err != nil {
			return err
		}
		if id == "" && fs.NArg() > 0 {
			id = fs.Arg(0)
		}
		if id == "" {
			return errors.New("usage: haptool fetch <package-or-appid> [--json]")
		}
		apps, err := client.FetchHarmonyFiles(ctx, id)
		if err != nil {
			return err
		}
		if jsonOut {
			return writeJSON(stdout, apps)
		}
		for _, a := range apps {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", a.Package, a.Version, a.VersionCode, a.BundleType)
			for _, f := range a.HapFiles {
				url := f.DownloadURL
				if url == "" && f.Compress != nil {
					url = f.Compress.DownloadURL
				}
				if url == "" {
					url = f.PackageURL
				}
				fmt.Fprintf(stdout, "  type=%d  size=%d  url=%s\n", f.FileType, f.FileSize, url)
			}
		}
		return nil
	case "download":
		fs := flag.NewFlagSet("download", flag.ContinueOnError)
		var id, output string
		fs.StringVar(&id, "id", "", "AppGallery C identifier or bundle name")
		fs.StringVar(&output, "output", "", "destination path")
		fs.StringVar(&output, "o", "", "destination path")
		if err := fs.Parse(flagsFirst(args[1:], map[string]bool{"--id": true, "-id": true, "--output": true, "-output": true, "-o": true})); err != nil {
			return err
		}
		if id == "" && fs.NArg() > 0 {
			id = fs.Arg(0)
		}
		if id == "" {
			return errors.New("usage: haptool download <app-id-or-bundle> [-o FILE]")
		}
		happs, harmonyErr := client.FetchHarmonyFiles(ctx, id)
		if harmonyErr == nil {
			for _, ha := range happs {
				if ha.Package == id || ha.AppID == id || id == "*" {
					if len(ha.HapFiles) != 1 {
						return errors.New("app does not contain exactly one HAP; inspect its modules with fetch or capture files")
					}
					url := ha.DownloadURL()
					if url != "" {
						dst := output
						if dst == "" {
							dst = ha.Package + "-" + ha.Version + ".hap"
						}
						file := ha.HapFiles[0]
						artifact := capture.Artifact{Package: ha.Package, Version: ha.Version, URL: url, SHA256: file.SHA256, Size: file.FileSize, Kind: "original"}
						if err := capture.Download(ctx, client.HTTPClient(), artifact, dst); err != nil {
							return err
						}
						fmt.Fprintf(stdout, "Downloaded %s %s to %s\n", ha.Package, ha.Version, dst)
						return nil
					}
					return errors.New("Harmony response has no usable original HAP URL; compressed or redacted files cannot be saved as HAPs")
				}
			}
		}
		a, err := client.Info(ctx, id)
		if err != nil {
			return err
		}
		if a.DownloadURL == "" {
			if harmonyErr != nil {
				return fmt.Errorf("Harmony fetch failed: %w; legacy AppGallery did not issue a package URL for this client session", harmonyErr)
			}
			return errors.New("AppGallery did not issue a package URL for this client session")
		}
		dst := output
		if dst == "" {
			dst = appgallery.DefaultFilename(a)
		}
		if err := download(ctx, client.HTTPClient(), a.DownloadURL, dst); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Downloaded %s %s to %s\n", a.Name, a.Version, dst)
		return nil
	case "web-check":
		id := "com.ss.hm.article.news"
		if len(args) > 1 {
			id = args[1]
		}
		a, err := client.WebInfo(ctx, id)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "App: %s %s\nInstall button: yes on HarmonyOS UA\nBrowser file download: no\nAction: store://appgallery.huawei.com/app/detail?id=%s\n", a.Name, a.Version, id)
		return nil
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// The standard flag package stops at the first positional argument. Moving
// recognized options to the front keeps both "search --limit 5 foo" and the
// more natural "search foo --limit 5" forms working.
func flagsFirst(args []string, takesValue map[string]bool) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := strings.SplitN(a, "=", 2)[0]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if takesValue[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

func authCommand(ctx context.Context, c *appgallery.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: haptool auth <login|info|revoke>")
	}
	switch args[0] {
	case "login":
		s, err := c.Login(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "AppGallery client session created for zone %s.\n", s.Zone)
		fmt.Fprintln(out, "This session is anonymous; Huawei ID authentication is not exposed by the public web flow.")
		return nil
	case "info":
		s, err := c.LoadSession()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Host: %s\nZone: %s\nCreated: %s\nExpires: %s\n", s.Host, s.Zone, s.CreatedAt.Format(time.RFC3339), s.CreatedAt.Add(24*time.Hour).Format(time.RFC3339))
		return nil
	case "revoke":
		return c.Revoke()
	default:
		return fmt.Errorf("unknown auth command %q", args[0])
	}
}

func download(ctx context.Context, hc *http.Client, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("download returned HTTP %s", res.Status)
	}
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".haptool-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err = io.Copy(tmp, res.Body); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, abs); err != nil {
		return err
	}
	ok = true
	return nil
}

func writeJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "haptool - search and download packages from Huawei AppGallery")
	fmt.Fprintln(w, "commands: auth, search, info, fetch, download, capture, web-check, version")
}
