package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFetchMemberRefusesWrongDigest pins fetchMember's central invariant: a
// wrong digest is never parsed and never left in the cache as if it were
// good. The cached copy already has the wrong digest (forcing a
// re-download), and the stubbed download also comes back wrong — so
// fetchMember must refuse rather than silently accept either one, and the
// cache file already on disk must survive untouched.
func TestFetchMemberRefusesWrongDigest(t *testing.T) {
	dir := t.TempDir()
	s := source{URL: "https://example.com/foo.zip", SHA256: strings.Repeat("a", 64), Member: "manual/bar.xml"}
	local := filepath.Join(dir, "foo.zip")
	cached := []byte("stale cached bytes, also wrong")
	if err := os.WriteFile(local, cached, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := download
	t.Cleanup(func() { download = orig })
	download = func(string) ([]byte, error) { return []byte("freshly downloaded bytes, still wrong"), nil }

	if _, _, err := fetchMember(dir, s); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v, want an error containing \"refusing\"", err)
	}

	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cached) {
		t.Errorf("cache file changed: got %q, want the original %q untouched", got, cached)
	}
}

// TestFetchMemberCachesAfterAGoodDownload covers the other half: a download
// whose digest matches the pin is accepted, its member returned, and the zip
// written to the cache — and a second call, with a download stub that must
// not be invoked, is answered entirely from that cache.
func TestFetchMemberCachesAfterAGoodDownload(t *testing.T) {
	dir := t.TempDir()
	const memberPath = "manual/bar.xml"
	memberBytes := []byte("<xml>hello</xml>")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(memberPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(memberBytes); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipBytes := buf.Bytes()
	sum := sha256.Sum256(zipBytes)
	sha := hex.EncodeToString(sum[:])
	s := source{URL: "https://example.com/foo.zip", SHA256: sha, Member: memberPath}

	orig := download
	t.Cleanup(func() { download = orig })
	download = func(string) ([]byte, error) { return zipBytes, nil }

	data, gotSHA, err := fetchMember(dir, s)
	if err != nil {
		t.Fatalf("fetchMember: %v", err)
	}
	if !bytes.Equal(data, memberBytes) {
		t.Errorf("member data = %q, want %q", data, memberBytes)
	}
	if gotSHA != sha {
		t.Errorf("sha = %q, want %q", gotSHA, sha)
	}

	local := filepath.Join(dir, "foo.zip")
	onDisk, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("cache file was not written: %v", err)
	}
	if !bytes.Equal(onDisk, zipBytes) {
		t.Error("cache file does not hold the downloaded zip")
	}

	// A second call must be answered from the now-good cache: the download
	// stub failing here would mean fetchMember reached the network again.
	download = func(string) ([]byte, error) { return nil, errors.New("network must not be used") }
	data2, _, err := fetchMember(dir, s)
	if err != nil {
		t.Fatalf("second fetchMember (cache hit): %v", err)
	}
	if !bytes.Equal(data2, memberBytes) {
		t.Errorf("second call data = %q, want %q from the cache", data2, memberBytes)
	}
}
