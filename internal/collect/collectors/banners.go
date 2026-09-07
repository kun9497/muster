//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// issuePath and issueNetPath are defined in sshd.go (R168) and reused here;
// do NOT redeclare them (one package, one definition).
const (
	motdPath  = "/etc/motd"
	motdDGlob = "/etc/update-motd.d/*"
)

var bannersCollector = collect.Collector{
	Name: "banners",
	Declare: collect.Declaration{
		Reads: []string{issuePath, issueNetPath, motdPath, motdDGlob},
		Needs: "none",
	},
	Run: runBanners,
}

func runBanners(_ context.Context, a collect.Access, b *collect.Builder) error {
	bannerContent(a, b, "banners.issue", issuePath, true)
	bannerContent(a, b, "banners.issue_net", issueNetPath, true)
	bannerContent(a, b, "banners.motd", motdPath, false)
	motdInventory(a, b)
	return nil
}

// bannerContent writes <prefix>.nonempty, <prefix>.mode and, when withEscapes,
// <prefix>.os_escapes. A file that is not there is a definite state: nonempty
// false, mode 0, os_escapes false. A file that cannot be READ (denied, a
// symlink the primitive refuses) carries that read's error on every leaf, so
// an unreadable banner is never a quiet "empty".
func bannerContent(a collect.Access, b *collect.Builder, prefix, p string, withEscapes bool) {
	data, meta, err := a.ReadFile(p, readLimit)
	src := &facts.Source{Kind: "file", Path: p}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			b.Set(prefix+".nonempty", collect.OK(false, src))
			b.Set(prefix+".mode", collect.OK(0, src))
			if withEscapes {
				b.Set(prefix+".os_escapes", collect.OK(false, src))
			}
			return
		}
		e := collect.FromReadError(err, meta)
		b.Set(prefix+".nonempty", e)
		b.Set(prefix+".mode", e)
		if withEscapes {
			b.Set(prefix+".os_escapes", e)
		}
		return
	}
	b.Set(prefix+".nonempty", collect.OKRead(len(strings.TrimSpace(string(data))) > 0, src, meta))
	b.Set(prefix+".mode", collect.OKRead(int(meta.Mode), src, meta))
	if withEscapes {
		b.Set(prefix+".os_escapes", collect.OKRead(osEscapes(data), src, meta))
	}
}

// osEscapes reports whether the banner leaks the distribution or version:
// an agetty/issue escape that expands to the release (\S \r \v \m \o \l) or
// the literal distribution name. Both families ship /etc/issue with the
// release string and \l, so a stock issue trips this and a control can note
// that a warning banner should not double as a version advertisement.
func osEscapes(data []byte) bool {
	return issueEscapeRe.Match(data) || distroNameRe.Match(data)
}

var (
	issueEscapeRe = regexp.MustCompile(`\\[Srvmol]`)
	distroNameRe  = regexp.MustCompile(`(?i)ubuntu|debian|rocky|alma|red hat|centos|fedora`)
)

// motdInventory lists /etc/update-motd.d and decides dynamic_motd. A script
// there means the real message of the day is generated at login, so the
// static /etc/motd check is structurally incomplete (spec §7.3 honesty).
func motdInventory(a collect.Access, b *collect.Builder) {
	matches, err := a.Glob(motdDGlob)
	src := &facts.Source{Kind: "file", Path: "/etc/update-motd.d"}
	if err != nil {
		e := collect.FromReadError(err, collect.ReadMeta{})
		b.Set("banners.motd_d", e)
		b.Set("banners.dynamic_motd", e)
		return
	}
	slices.Sort(matches)
	list := []any{}
	dynamic := false
	for _, m := range matches {
		meta, serr := a.Stat(m)
		executable := serr == nil && meta.Mode&0o111 != 0
		if executable {
			dynamic = true
		}
		list = append(list, map[string]any{
			"name":       path.Base(m),
			"executable": executable,
		})
	}
	b.Set("banners.motd_d", collect.OK(list, src))
	b.Set("banners.dynamic_motd", collect.OK(dynamic, src))
}
