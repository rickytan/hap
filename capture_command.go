package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rickytan/haptool/internal/capture"
)

func captureCommand(ctx context.Context, args []string, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: haptool capture <inspect|replay|files|download> <HAR> [--entry N] [--file N] [-o PATH]")
	}
	switch args[0] {
	case "inspect", "replay", "files", "download":
	default:
		return errors.New("unknown capture command")
	}
	fs := flag.NewFlagSet("capture "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	entry := fs.Int("entry", -1, "HAR entry index (shown by inspect)")
	file := fs.Int("file", -1, "artifact index (shown by files)")
	dst := fs.String("o", "", "new output file; existing files are never overwritten")
	responseOnly := fs.Bool("response", false, "read a saved response JSON instead of HAR (files/download only)")
	if err := fs.Parse(flagsFirst(args[1:], map[string]bool{"--entry": true, "-entry": true, "--file": true, "-file": true, "-o": true})); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("provide exactly one input file")
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()
	var entries []capture.Entry
	var responseBody []byte
	if *responseOnly {
		if args[0] != "files" && args[0] != "download" {
			return errors.New("--response supports only files/download")
		}
		responseBody, err = io.ReadAll(io.LimitReader(f, capture.MaxCaptureBytes+1))
		if err != nil {
			return err
		}
		if len(responseBody) > capture.MaxCaptureBytes {
			return errors.New("response exceeds 64 MiB limit")
		}
	} else {
		entries, err = capture.ReadHAR(f)
		if err != nil {
			return err
		}
	}
	if args[0] == "inspect" {
		summaries := []map[string]any{}
		for i, e := range entries {
			if e.Harmony() {
				summaries = append(summaries, e.Summary(i))
			}
		}
		return writeJSON(out, map[string]any{"totalEntries": len(entries), "harmonyEntries": summaries})
	}
	var e capture.Entry
	if !*responseOnly {
		if *entry < 0 || *entry >= len(entries) {
			return errors.New("select a valid --entry from capture inspect")
		}
		e = entries[*entry]
		if !e.Harmony() {
			return errors.New("selected entry is not a Huawei Harmony request")
		}
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	switch args[0] {
	case "replay":
		if *dst == "" {
			return errors.New("replay requires -o RESPONSE.json (may contain credentials)")
		}
		// Reserve a private output before making a network request.
		f, err := os.OpenFile(*dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		ok := false
		defer func() {
			f.Close()
			if !ok {
				os.Remove(*dst)
			}
		}()
		body, status, err := e.Replay(ctx, client)
		if err != nil {
			return err
		}
		if _, err := f.Write(body); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		ok = true
		fmt.Fprintf(out, "HTTP %d; response saved to %s\n", status, *dst)
		if status != http.StatusOK {
			return fmt.Errorf("replay returned HTTP %d; inspect saved response", status)
		}
		return capture.CheckResponse(body)
	case "files", "download":
		body := responseBody
		if !*responseOnly {
			body, err = e.ResponseBody()
			if err != nil {
				return err
			}
		}
		artifacts, err := capture.Artifacts(body)
		if err != nil {
			return err
		}
		if args[0] == "files" {
			for i, a := range artifacts {
				fmt.Fprintf(out, "%d\t%s\t%s\t%s\t%d bytes\tsha256=%s\tstatus=%s\tencType=%d\tcompressType=%d\n", i, a.Package, a.Version, a.Kind, a.Size, a.SHA256, a.Availability(), a.EncryptionType, a.CompressionType)
			}
			return nil
		}
		if *file < 0 || *file >= len(artifacts) || *dst == "" {
			return errors.New("download requires --file N and -o FILE.hap")
		}
		if err := capture.Download(ctx, client, artifacts[*file], *dst); err != nil {
			return err
		}
		fmt.Fprintf(out, "Downloaded %s; SHA-256, size and HAP structure verified\n", *dst)
		return nil
	default:
		return errors.New("unknown capture command")
	}
}
