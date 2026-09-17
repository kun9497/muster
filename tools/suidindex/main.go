// Command suidindex builds docs/reference/suid/<distro>-<version>.json —
// the reference lists the walk's package join reads (W-7) — by running a
// pinned public container image and asking the distribution's own package
// tool what it ships and with what mode.
//
// It is a maintainer tool, exactly as tools/refindex is: CI never runs it
// and never reaches a registry or an archive. What CI has is the committed
// lists, the shape test in docs/reference/suid and, on a machine with a
// container runtime, `suidindex -check`, which regenerates to memory and
// compares the bytes.
//
// Three modes:
//
//	suidindex                 regenerate every release's list and write it
//	suidindex -check          regenerate to memory and diff, exit 1 on drift
//	suidindex -resolve        pin an image's digest and an archive's URL
//
// -platform (default linux/amd64) is what the image is pulled and run for and
// what the list records as its `arch`; the image's own `uname -m` has to
// agree, so a runtime that quietly served an emulated image of another
// architecture cannot produce a list labelled with this one.
//
// The packages a list covers are a SEED UNIONED WITH A DISCOVERY: sources.json
// names the ones a maintainer cares about, and the script inside the image
// adds the owning package of every setuid and setgid file the image carries
// (`find / -xdev -perm /6000 -type f`, then `dpkg -S` or `rpm -qf`). That is
// why a generated list covers mount, libpam-modules-bin and usermode, which
// nobody wrote down: a base image installs things nobody thought to list, and
// a package the join meets but the list does not cover reads `unlisted` and
// can only warn. A seed the image does not install and that pins no archive
// is dropped with a warning — the generator installs nothing, because a list
// has to be reproducible from the pinned image digest alone.
//
// -resolve is the only mode that asks the archive what the current version
// is; it prints the image digest and, per extended package, the `.deb` URL
// `apt-get download --print-uris` reports inside the image together with the
// SHA-256 this tool computed by downloading it. The maintainer pastes both
// into sources.json, and from then on the SHA-256 is the pin: a URL that
// rotates fails loudly at download rather than quietly regenerating a
// different list (ruling A-37).
//
// The archives are downloaded on the HOST, with net/http, because the stock
// images ship no curl and no wget; each is verified against its pin BEFORE
// it is opened and the directory is bind-mounted read-only into the
// container. A generating container is given no network and installs
// nothing: a list must be reproducible from the pinned digest and the pinned
// archives alone. Only -resolve, whose whole purpose is to ask what the
// archive carries today, runs with one.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kun9497/muster/docs/reference/suid"
)

// errStale is -check's answer: the committed lists are not what this run
// produces. It is separated from a real failure so the exit codes can be
// told apart the way tools/refindex tells them apart — 1 for "out of date",
// 2 for "could not tell".
var errStale = errors.New("the committed lists are out of date")

// packageName is what a package name may look like before it is pasted into
// a shell script. Debian and RPM both allow letters, digits and + - . _ ; a
// name outside that set is refused rather than quoted around, because the
// script is assembled by string substitution and a quoting bug there would
// run the maintainer's shell against a value from a JSON file.
var packageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]*$`)

// runTimeout bounds one container run. The dpkg releases walk every file of
// a dozen packages with a stat apiece, which is minutes on a slow disk and
// nothing like an hour.
const runTimeout = 20 * time.Minute

type options struct {
	sourcesPath string
	outDir      string
	cacheDir    string
	runtime     string
	platform    string
	arch        string
	generated   string
	only        string
	check       bool
	resolve     bool
}

// defaultPlatform is the one the committed lists were generated for. A
// distribution can ship a binary setuid on one architecture and not on
// another, and a runtime on an arm64 machine will happily serve an emulated
// amd64 image (or the reverse) without saying so — so the platform is asked
// for explicitly, recorded in the list, and cross-checked against the
// image's own `uname -m`.
const defaultPlatform = "linux/amd64"

func main() {
	var o options
	flag.StringVar(&o.sourcesPath, "sources", "docs/reference/suid/sources.json", "the pinned images and packages")
	flag.StringVar(&o.outDir, "out", "docs/reference/suid", "output directory")
	flag.StringVar(&o.cacheDir, "cache", ".cache/suidindex", "download cache directory (git-ignored)")
	flag.StringVar(&o.runtime, "runtime", "docker", "container runtime: docker or podman")
	flag.StringVar(&o.platform, "platform", defaultPlatform, "the image platform to pull and record")
	flag.StringVar(&o.generated, "generated", "", "the date to stamp into `generated` (default: today, UTC)")
	flag.StringVar(&o.only, "release", "", "generate only this release, as id-version_id")
	flag.BoolVar(&o.check, "check", false, "regenerate to memory and exit 1 if the committed files differ")
	flag.BoolVar(&o.resolve, "resolve", false, "print the image digest and the archive URLs and digests to pin")
	flag.Parse()
	switch err := run(o, os.Stderr); {
	case err == nil:
	case errors.Is(err, errStale):
		fmt.Fprintf(os.Stderr, "suidindex: %v; run: go run ./tools/suidindex\n", err)
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "suidindex: %v\n", err)
		os.Exit(2)
	}
}

// run is the whole tool, with the container runtime and the network behind
// the two package-level variables below, so the check path is tested on a
// host that has neither.
func run(o options, stderr io.Writer) error {
	sources, err := loadSources(o.sourcesPath)
	if err != nil {
		return err
	}
	if o.platform == "" {
		o.platform = defaultPlatform
	}
	if o.arch == "" {
		_, arch, ok := strings.Cut(o.platform, "/")
		if !ok || arch == "" {
			return fmt.Errorf("-platform %q is not <os>/<arch>", o.platform)
		}
		o.arch = arch
	}
	generated := o.generated
	if generated == "" {
		generated = time.Now().UTC().Format("2006-01-02")
	}
	stale := false
	matched := false
	for _, rel := range sources.Releases {
		name := rel.ID + "-" + rel.VersionID
		if o.only != "" && o.only != name {
			continue
		}
		matched = true
		if o.resolve {
			if err := resolveRelease(o, rel, stderr); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		list, warnings, err := generateRelease(o, rel, generated)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		for _, w := range warnings {
			fmt.Fprintf(stderr, "suidindex: %s: %s\n", name, w)
		}
		blob, err := renderList(list)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		// The file is named from the IMAGE's own VERSION_ID, which is a
		// point release on the RHEL family; suid.Load falls back from the
		// host's version to the major (A-36).
		path := filepath.Join(o.outDir, list.Distro+"-"+list.Release+".json")
		if o.check {
			have, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(stderr, "suidindex: %s cannot be read: %v\n", path, err)
				stale = true
				continue
			}
			switch msg, kind := describeDifference(have, blob); kind {
			case diffReal:
				fmt.Fprintf(stderr, "suidindex: %s is out of date: %s\n", path, msg)
				stale = true
			case diffDateOnly:
				// Not drift: the clock. -check has to be usable on a day
				// that is not the day the lists were generated.
				fmt.Fprintf(stderr, "suidindex: %s matches; %s\n", path, msg)
			}
			continue
		}
		if err := os.MkdirAll(o.outDir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, blob, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "suidindex: wrote %s (%d packages, %d files)\n", path, len(list.Packages), len(list.Entries))
	}
	if !matched {
		return fmt.Errorf("-release %q matches no release in %s", o.only, o.sourcesPath)
	}
	if stale {
		return errStale
	}
	return nil
}

// loadSources decodes sources.json from a path — the embedded copy is what
// the collector reads, and the tool must be able to run against a working
// tree — with the same strictness suid.LoadSources uses: an unknown field is
// an error, so a typo cannot silently drop a package from the input.
func loadSources(path string) (*suid.Sources, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s suid.Sources
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(s.Releases) == 0 {
		return nil, fmt.Errorf("%s: no releases", path)
	}
	return &s, nil
}

// generateRelease stages the pinned archives, runs the script in the pinned
// image and assembles the list.
func generateRelease(o options, rel suid.Release, generated string) (suid.List, []string, error) {
	if rel.Digest == "" {
		return suid.List{}, nil, fmt.Errorf("the image digest is still a placeholder; run -resolve to pin it")
	}
	script, err := scriptFor(rel)
	if err != nil {
		return suid.List{}, nil, err
	}
	debs, err := os.MkdirTemp("", "suidindex-debs-")
	if err != nil {
		return suid.List{}, nil, err
	}
	defer os.RemoveAll(debs)
	// 0o755, not the 0o700 MkdirTemp gives: the bind mount is read by root
	// inside the container, and a user-namespaced runtime maps that root to
	// somebody who is not this user.
	if err := os.Chmod(debs, 0o755); err != nil {
		return suid.List{}, nil, err
	}
	for _, p := range rel.Packages {
		if p.URL == "" {
			continue
		}
		blob, err := fetchArchive(o.cacheDir, p)
		if err != nil {
			return suid.List{}, nil, err
		}
		if err := os.WriteFile(filepath.Join(debs, p.Name+".deb"), blob, 0o644); err != nil {
			return suid.List{}, nil, err
		}
	}
	out, err := runScript(o, rel.Image+"@"+rel.Digest, debs, script, false)
	if err != nil {
		return suid.List{}, nil, err
	}
	return assembleList(rel, generated, o.arch, out)
}

// fetchArchive returns one pinned .deb, from the cache when the cached copy
// still matches the pin and from the network otherwise. The digest is
// verified before the bytes are written anywhere or handed to a container:
// the URL is a convenience and the SHA-256 is the pin (A-37).
func fetchArchive(cache string, p suid.SourcePackage) ([]byte, error) {
	if p.SHA256 == "" {
		return nil, fmt.Errorf("package %s: a url with no sha256; run -resolve", p.Name)
	}
	local := filepath.Join(cache, cacheName(p))
	if blob, err := os.ReadFile(local); err == nil && digest256(blob) == p.SHA256 {
		return blob, nil
	}
	blob, err := download(p.URL)
	if err != nil {
		return nil, fmt.Errorf("package %s: %w", p.Name, err)
	}
	if got := digest256(blob); got != p.SHA256 {
		return nil, fmt.Errorf("package %s: %s has sha256 %s, pinned %s — refusing", p.Name, p.URL, got, p.SHA256)
	}
	if err := os.MkdirAll(cache, 0o755); err == nil {
		_ = os.WriteFile(local, blob, 0o644)
	}
	return blob, nil
}

// cacheName is the cached archive's file name. It leads with the pinned
// digest because two releases can pin DIFFERENT archives under one file name
// — mtr-tiny_0.95-1_amd64.deb is a different file on Ubuntu and on Debian —
// and a cache keyed by the name alone would make each release evict the
// other's copy on every run. Everything a file name may not hold is folded
// away: the name is a convenience for a person reading the cache directory,
// and the digest is what identifies the file.
func cacheName(p suid.SourcePackage) string {
	base := filepath.Base(p.URL)
	safe := strings.Map(func(r rune) rune {
		if r == '.' || r == '_' || r == '-' || (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return '_'
	}, base)
	return p.SHA256[:12] + "-" + safe
}

// resolveRelease prints what a maintainer pastes into sources.json: the
// image's digest, and per EXTENDED package the archive URL the image's own
// apt resolves today together with the SHA-256 of the file that URL served.
//
// "Extended" is not a flag in sources.json — it is a fact about the image: a
// package the image installs is read out of the image and needs no archive,
// and a package it does not install is downloaded. The same rule decides it
// here and in scriptFor, so the two can never disagree about which packages
// need a pin.
func resolveRelease(o options, rel suid.Release, out io.Writer) error {
	fmt.Fprintf(out, "\n# %s-%s (%s)\n", rel.ID, rel.VersionID, rel.Image)
	imgDigest, err := imageDigest(o, rel.Image)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  \"digest\": %q,\n", imgDigest)
	if family(rel.ID) != "dpkg" {
		fmt.Fprintf(out, "#   %s is an rpm release: its list covers what the image installs and pins no archive\n", rel.ID)
		return nil
	}
	var named []string
	for _, p := range rel.Packages {
		if !packageName.MatchString(p.Name) {
			return fmt.Errorf("package %q is not a package name", p.Name)
		}
		named = append(named, p.Name)
	}
	script := "set -u\nnamed='" + strings.Join(named, " ") + `'
apt-get update -qq >/dev/null 2>&1
want=''
for p in $named; do
  if ! dpkg-query -W "$p" >/dev/null 2>&1; then want="$want $p"; fi
done
if [ -n "$want" ]; then apt-get download --print-uris $want 2>/dev/null; fi
`
	printed, err := runScript(o, rel.Image+"@"+imgDigest, "", script, true)
	if err != nil {
		return err
	}
	urls := parsePrintURIs(string(printed))
	for _, p := range rel.Packages {
		url, ok := urls[p.Name]
		if !ok {
			fmt.Fprintf(out, "#   %s: the image installs it, or apt resolved no archive\n", p.Name)
			continue
		}
		blob, err := download(url)
		if err != nil {
			fmt.Fprintf(out, "#   %s: %v\n", p.Name, err)
			continue
		}
		fmt.Fprintf(out, "  {\"name\": %q, \"reason\": %q, \"url\": %q, \"sha256\": %q},\n", p.Name, p.Reason, url, digest256(blob))
	}
	return nil
}

// parsePrintURIs reads `apt-get download --print-uris`:
//
//	'http://…/pool/main/a/at/at_3.2.5-1ubuntu1_amd64.deb' at_3.2.5-1ubuntu1_amd64.deb 41108 SHA512:…
//
// The package name is the part of the FILE name before the first underscore,
// which is how both Debian and Ubuntu name a .deb; the SHA-512 apt prints is
// ignored, because the pin this tool keeps is the SHA-256 it computes from
// the bytes it actually downloaded.
func parsePrintURIs(out string) map[string]string {
	urls := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || !strings.HasPrefix(f[0], "'") {
			continue
		}
		url := strings.Trim(f[0], "'")
		name, _, ok := strings.Cut(f[1], "_")
		if !ok || name == "" {
			continue
		}
		urls[name] = url
	}
	return urls
}

// family names the package tool of a distribution id. An id this tool has
// never been taught is an error, never a guess: a list generated with the
// wrong tool would be empty rather than wrong, which is worse.
func family(id string) string {
	switch id {
	case "ubuntu", "debian":
		return "dpkg"
	case "rocky", "almalinux", "rhel", "centos":
		return "rpm"
	}
	return ""
}

// scriptFor is the shell script one image runs. It prints the document
// parse.go reads: the image's own identity and merged-usr table, then, for
// every package the list covers, its version and a line per file.
//
// The covered packages are the owners of every setuid/setgid file the image
// carries, unioned with the ones sources.json names — the discovery finds
// what a base image installs that nobody thought to list, and the names make
// sure a package the image does install is covered even when nothing in it
// happens to be setuid. A named package the image does NOT install is
// dropped here and warned about in parse.go: the script may not install
// anything, because a list has to be reproducible from the pinned digest and
// an archive that moves under it is not.
func scriptFor(rel suid.Release) (string, error) {
	fam := family(rel.ID)
	if fam == "" {
		return "", fmt.Errorf("no package tool is known for distro id %q", rel.ID)
	}
	var named, archives []string
	for _, p := range rel.Packages {
		if !packageName.MatchString(p.Name) {
			return "", fmt.Errorf("package %q is not a package name", p.Name)
		}
		if p.URL != "" {
			if fam != "dpkg" {
				return "", fmt.Errorf("package %s: only the dpkg family downloads archives", p.Name)
			}
			archives = append(archives, p.Name)
			continue
		}
		named = append(named, p.Name)
	}

	var b strings.Builder
	b.WriteString("set -u\n")
	b.WriteString("echo '== osrelease'\n. /etc/os-release\nprintf '%s\\n%s\\n' \"$ID\" \"$VERSION_ID\"\n")
	b.WriteString("echo '== arch'\nuname -m\n")
	b.WriteString("echo '== usrmerge'\n")
	b.WriteString("for d in " + strings.Join(usrAliases, " ") + "; do\n")
	b.WriteString("  if [ -L \"$d\" ]; then printf '%s %s\\n' \"$d\" \"$(readlink \"$d\")\"; fi\n")
	b.WriteString("done\n")
	b.WriteString("named='" + strings.Join(named, " ") + "'\n")
	b.WriteString("archives='" + strings.Join(archives, " ") + "'\n")

	switch fam {
	case "dpkg":
		b.WriteString(`owner() {
  p=$(dpkg -S "$1" 2>/dev/null | head -n1 | cut -d: -f1)
  if [ -z "$p" ]; then
    a=$(printf '%s' "$1" | sed 's|^/usr/|/|')
    p=$(grep -l -x -F -e "$1" -e "$a" /var/lib/dpkg/info/*.list 2>/dev/null | head -n1 | sed 's|.*/||; s|\.list$||; s|:.*||')
  fi
  printf '%s\n' "$p"
}
found=$(find / -xdev -perm /6000 -type f 2>/dev/null | while IFS= read -r f; do owner "$f"; done)
pkgs=$(printf '%s\n%s\n' "$named" "$found" | tr ' ' '\n' | sed '/^$/d' | sort -u | while IFS= read -r p; do
  if dpkg-query -W -f '${Package}\n' "$p" >/dev/null 2>&1; then printf '%s\n' "$p"; fi
done)
echo '== versions'
for p in $pkgs; do dpkg-query -W -f '${Package} ${Version}\n' "$p" 2>/dev/null | head -n1; done
for d in $archives; do printf '%s %s\n' "$d" "$(dpkg-deb -f "/debs/$d.deb" Version)"; done
for p in $pkgs; do
  printf '== files %s\n' "$p"
  dpkg -L "$p" 2>/dev/null | while IFS= read -r f; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then stat -c '%a %U %G %n' "$f"; fi
  done
done
for d in $archives; do
  printf '== modes %s\n' "$d"
  rm -rf /tmp/suidindex-control
  mkdir -p /tmp/suidindex-control
  dpkg-deb -e "/debs/$d.deb" /tmp/suidindex-control 2>/dev/null
  grep -hE 'chmod|dpkg-statoverride' /tmp/suidindex-control/* 2>/dev/null
  printf '== deb %s %s\n' "$d" "$(sha256sum "/debs/$d.deb" | cut -d' ' -f1)"
  dpkg-deb --fsys-tarfile "/debs/$d.deb" | tar -tv | grep -v '^[dlhcbps]'
done
`)
	case "rpm":
		b.WriteString(`found=$(find / -xdev -perm /6000 -type f 2>/dev/null | while IFS= read -r f; do
  rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null
done)
pkgs=$(printf '%s\n%s\n' "$named" "$found" | tr ' ' '\n' | sed '/^$/d' | sort -u | while IFS= read -r p; do
  if rpm -q "$p" >/dev/null 2>&1; then printf '%s\n' "$p"; fi
done)
echo '== versions'
for p in $pkgs; do rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null | head -n1; done
for p in $pkgs; do
  printf '== files %s\n' "$p"
  rpm -ql "$p" 2>/dev/null | while IFS= read -r f; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then stat -c '%a %U %G %n' "$f"; fi
  done
done
`)
	}
	return b.String(), nil
}

// runScript runs one script inside one image, mounting the staged archives
// read-only when there are any. Generation runs with NO network: a list has
// to be reproducible from the pinned digest and the pinned archives alone,
// and an image that could reach an archive could install something that no
// later run would install again. Only -resolve, which exists to ask the
// archive what it carries today, is given one. A package-level var so the
// tests drive the whole check path from a recorded document, on a host with
// no container runtime.
var runScript = func(o options, image, debsDir, script string, network bool) ([]byte, error) {
	args := []string{"run", "--rm", "--platform", o.platform, "--entrypoint", "sh"}
	if !network {
		args = append(args, "--network", "none")
	}
	if debsDir != "" {
		args = append(args, "-v", debsDir+":/debs:ro")
	}
	args = append(args, image, "-c", script)
	return runRuntime(o, args...)
}

// imageDigest pulls an image for the pinned platform and reports the digest
// to pin it by.
func imageDigest(o options, image string) (string, error) {
	if _, err := runRuntime(o, "pull", "--quiet", "--platform", o.platform, image); err != nil {
		return "", err
	}
	out, err := runRuntime(o, "image", "inspect", "--format", "{{json .RepoDigests}}", image)
	if err != nil {
		return "", err
	}
	var repoDigests []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &repoDigests); err != nil {
		return "", fmt.Errorf("%s: cannot read RepoDigests: %w", image, err)
	}
	return matchingDigest(image, repoDigests)
}

// matchingDigest picks the RepoDigests entry for the repository that was
// ASKED for. A local image is known by every repository it was ever tagged
// or pulled under, in no order the caller controls, so taking the first
// would pin a list to whatever else happened to share the image id — a
// mirror, or another distribution's tag. No entry for the requested
// repository is a refusal: a digest guessed from a different name would be
// recorded in the list and in sources.json as if it had been verified.
func matchingDigest(image string, repoDigests []string) (string, error) {
	want := normalizeRepo(repoOf(image))
	for _, rd := range repoDigests {
		repo, digest, ok := strings.Cut(rd, "@")
		if !ok {
			continue
		}
		if normalizeRepo(repo) == want {
			return digest, nil
		}
	}
	return "", fmt.Errorf("%s: no RepoDigests entry for %s (have %v) — pull it and try again", image, want, repoDigests)
}

// repoOf drops an image reference's tag. The colon that introduces a tag is
// the one AFTER the last slash; a registry may carry a port ("host:5000/x"),
// whose colon comes before it.
func repoOf(image string) string {
	i := strings.LastIndexByte(image, ':')
	if i < 0 || i < strings.LastIndexByte(image, '/') {
		return image
	}
	return image[:i]
}

// normalizeRepo spells a Docker Hub repository the one way, so the
// docker.io/library/ubuntu a maintainer writes in sources.json and the
// ubuntu the runtime reports are the same repository.
func normalizeRepo(repo string) string {
	repo = strings.TrimPrefix(repo, "docker.io/")
	repo = strings.TrimPrefix(repo, "index.docker.io/")
	return strings.TrimPrefix(repo, "library/")
}

// runRuntime runs the container runtime and returns its stdout. A non-zero
// exit carries the first of stderr, which is where a pull failure or a
// missing image says what went wrong.
var runRuntime = func(o options, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.runtime, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg != "" {
			return nil, fmt.Errorf("%s %s: %w: %s", o.runtime, args[0], err, msg)
		}
		return nil, fmt.Errorf("%s %s: %w", o.runtime, args[0], err)
	}
	return out, nil
}

// download GETs one archive. A package-level var, as in tools/refindex, so a
// test can drive fetchArchive without reaching the network.
var download = func(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	req.Header.Set("User-Agent", "muster-suidindex")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func digest256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
