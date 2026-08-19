package perm

import (
	"regexp"
	"strings"
	"testing"

	"github.com/apple/pkl-go/pkl"
)

// admits reports whether an allowlist would let Pkl load uri.
//
// Pkl tests each pattern against the beginning of the URI — java.util.regex's
// lookingAt, which is anchored at the start and open at the end. Go's
// MatchString is unanchored at both ends, so the "^" is what makes this
// equivalent rather than merely similar. Every pattern the package generates
// uses only QuoteMeta output and (:\d+)?, which mean the same thing in both
// dialects.
func admits(t *testing.T, patterns []string, uri string) bool {
	t.Helper()
	for _, p := range patterns {
		re, err := regexp.Compile("^" + p)
		if err != nil {
			t.Fatalf("pattern %q does not compile: %v", p, err)
		}
		if re.MatchString(uri) {
			return true
		}
	}
	return false
}

func applied(t *testing.T, s *Set) *pkl.EvaluatorOptions {
	t.Helper()
	if err := s.Resolve(t.TempDir()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	o := &pkl.EvaluatorOptions{}
	s.Apply(o)
	return o
}

// TestSuffixConfusion is the reason hostPatterns appends a trailing slash.
//
// Without it "example.com" is a prefix of "example.com.evil.net", and an
// attacker who controls any domain suffixed onto an allowed one inherits the
// grant. Verified against pkl 0.32.1, where a pattern of ".../a" does admit
// ".../ab/x.pkl".
func TestSuffixConfusion(t *testing.T) {
	o := applied(t, &Set{Net: []string{"example.com"}})

	allowed := []string{
		"https://example.com/",
		"https://example.com/schema.pkl",
		"https://example.com:8443/schema.pkl",
	}
	for _, uri := range allowed {
		if !admits(t, o.AllowedModules, uri) {
			t.Errorf("allowing example.com should admit %q", uri)
		}
	}

	refused := []string{
		"https://example.com.evil.net/x.pkl",
		"https://example.completely-different.example/x.pkl",
		"https://evil.net/?u=https://example.com/",
		"http://example.com/x.pkl", // plaintext needs an explicit scheme
	}
	for _, uri := range refused {
		if admits(t, o.AllowedModules, uri) {
			t.Errorf("allowing example.com must NOT admit %q", uri)
		}
	}
}

func TestPathPrefixPinning(t *testing.T) {
	o := applied(t, &Set{Net: []string{"raw.githubusercontent.com/idleberg/pklenv/v0.1.0"}})

	if !admits(t, o.AllowedModules, "https://raw.githubusercontent.com/idleberg/pklenv/v0.1.0/schema/PklEnv.pkl") {
		t.Error("the pinned tree should be admitted")
	}
	// Another repo on the same host is the case host-only pinning cannot express,
	// and raw.githubusercontent.com serves every repository on GitHub.
	for _, uri := range []string{
		"https://raw.githubusercontent.com/attacker/evil/main/x.pkl",
		"https://raw.githubusercontent.com/idleberg/pklenv/v9.9.9/x.pkl",
		"https://raw.githubusercontent.com/idleberg/pklenv/v0.1.0-rc1/x.pkl",
	} {
		if admits(t, o.AllowedModules, uri) {
			t.Errorf("pinning a path must NOT admit %q", uri)
		}
	}
}

func TestExplicitSchemeAndPackages(t *testing.T) {
	https := applied(t, &Set{Net: []string{"example.com"}})
	if !admits(t, https.AllowedModules, "package://example.com/pklenv@1.0.0") {
		t.Error("an https host should also serve its packages")
	}

	plain := applied(t, &Set{Net: []string{"http://internal.example"}})
	if !admits(t, plain.AllowedModules, "http://internal.example/x.pkl") {
		t.Error("an explicit http:// scheme should be honoured")
	}
	if admits(t, plain.AllowedModules, "package://internal.example/x@1.0.0") {
		t.Error("package: resolves over https and must not follow a plaintext grant")
	}
}

func TestNetDefaultDeniesEverything(t *testing.T) {
	o := applied(t, &Set{})
	for _, uri := range []string{
		"https://example.com/x.pkl",
		"http://example.com/x.pkl",
		"package://pkg.pkl-lang.org/x@1.0.0",
	} {
		if admits(t, o.AllowedModules, uri) {
			t.Errorf("the default posture must refuse %q", uri)
		}
		if admits(t, o.AllowedResources, uri) {
			t.Errorf("the default posture must refuse resource %q", uri)
		}
	}
}

func TestNetAllOpensAnyHost(t *testing.T) {
	o := applied(t, &Set{NetAll: true})
	if !admits(t, o.AllowedModules, "https://anything.example/x.pkl") {
		t.Error("a bare --allow-net should admit any https host")
	}
}

// TestEnvGrantIsExact guards the $ anchor. Pkl matches from the beginning of
// the URI, so an unanchored "env:FOO" also admits "env:FOO_BAR" — confirmed
// against pkl 0.32.1.
func TestEnvGrantIsExact(t *testing.T) {
	o := applied(t, &Set{Env: []string{"FOO", "CI_DEPLOY_TOKEN"}, EnvSet: true})

	for _, uri := range []string{"env:FOO", "env:CI_DEPLOY_TOKEN"} {
		if !admits(t, o.AllowedResources, uri) {
			t.Errorf("granted %q should be readable", uri)
		}
	}
	for _, uri := range []string{"env:FOO_BAR", "env:AWS_SECRET_ACCESS_KEY", "env:CI_DEPLOY_TOKEN_2"} {
		if admits(t, o.AllowedResources, uri) {
			t.Errorf("a grant of FOO must NOT admit %q", uri)
		}
	}
}

func TestEnvDefaultsToEverythingAndEmptyMeansNothing(t *testing.T) {
	open := applied(t, &Set{})
	if !admits(t, open.AllowedResources, "env:ANYTHING") {
		t.Error("without --allow-env every variable stays readable")
	}

	// --allow-env with no value: the user asked for nothing, which is not the
	// same as not asking.
	shut := applied(t, &Set{EnvSet: true})
	if admits(t, shut.AllowedResources, "env:ANYTHING") {
		t.Error("an empty grant must deny every variable")
	}
}

func TestPropAndStdlibStayReachable(t *testing.T) {
	o := applied(t, &Set{})
	// The standard library reads this while rendering output; refusing it fails
	// every evaluation before a config gets a say.
	if !admits(t, o.AllowedResources, "prop:pkl.outputFormat") {
		t.Error("prop: must always be allowed")
	}
	if !admits(t, o.AllowedModules, "pkl:base") {
		t.Error("the standard library must always be allowed")
	}
}

func TestRootDirDefaultsToWorkingDirAndCanBeDisabled(t *testing.T) {
	wd := t.TempDir()

	var implicit Set
	if err := implicit.Resolve(wd); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// EvalSymlinks, because macOS temp dirs live under /var -> /private/var and
	// Pkl resolves symlinks before testing the boundary.
	if implicit.RootDir == "" || !strings.HasSuffix(implicit.RootDir, strings.TrimPrefix(wd, "/private")) {
		t.Errorf("RootDir should default to the working dir, got %q for wd %q", implicit.RootDir, wd)
	}

	explicit := Set{rootDirSet: true, RootDir: ""}
	if err := explicit.Resolve(wd); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if explicit.RootDir != "" {
		t.Errorf("--root-dir='' should disable the boundary, got %q", explicit.RootDir)
	}
}

// TestProjectPackageNeedsABareAllowNet pins the one grant that cannot be scoped
// to a host. projectpackage: resolves through a project's PklProject.deps.json
// rather than over the wire, and pklenv never sets ProjectDir — so naming a host
// must not drag it along, where it would read as a host-scoped grant while being
// an unscoped one.
func TestProjectPackageNeedsABareAllowNet(t *testing.T) {
	const uri = "projectpackage://elsewhere.example/pkg@1.0.0#/x.pkl"

	scoped := applied(t, &Set{Net: []string{"example.com"}})
	if admits(t, scoped.AllowedModules, uri) {
		t.Error("allowing one host must NOT admit projectpackage: for any host")
	}
	if admits(t, scoped.AllowedResources, uri) {
		t.Error("allowing one host must NOT admit projectpackage: resources")
	}

	// --allow-net with no value means any host, where an unscoped prefix is the
	// literal intent rather than an accident.
	all := applied(t, &Set{NetAll: true})
	if !admits(t, all.AllowedModules, uri) {
		t.Error("a bare --allow-net should admit projectpackage:")
	}
}

// TestIPv6LiteralHosts pins behaviour that currently works by construction: an
// address has no slash, so the path cut leaves it intact, and QuoteMeta escapes
// its brackets. A simplification of the host parsing would quietly break it.
func TestIPv6LiteralHosts(t *testing.T) {
	o := applied(t, &Set{Net: []string{"[::1]"}})
	for _, uri := range []string{
		"https://[::1]/x.pkl",
		"https://[::1]:8080/x.pkl",
	} {
		if !admits(t, o.AllowedModules, uri) {
			t.Errorf("a bracketed IPv6 grant should admit %q", uri)
		}
	}
	if admits(t, o.AllowedModules, "https://[::2]/x.pkl") {
		t.Error("an IPv6 grant must not admit a different address")
	}
}

// TestHostGrantIsCaseInsensitive guards a silent no-op. A host is
// case-insensitive and reaches Pkl lowercased, so without folding, --allow-net
// =EXAMPLE.com would be accepted as valid and then refuse every URL it names.
func TestHostGrantIsCaseInsensitive(t *testing.T) {
	o := applied(t, &Set{Net: []string{"EXAMPLE.com/Some/Path"}})
	if !admits(t, o.AllowedModules, "https://example.com/Some/Path/x.pkl") {
		t.Error("a mixed-case host should name the same host as its lowercase form")
	}
	// The path is not folded with it: there, case is the server's business.
	if admits(t, o.AllowedModules, "https://example.com/some/path/x.pkl") {
		t.Error("a path prefix must stay case-sensitive")
	}
}

func TestMalformedNetEntriesAreRejected(t *testing.T) {
	for _, entry := range []string{
		"ftp://example.com",
		"/no-host",
		"user@example.com",
		// Refused rather than matched: the URI Pkl tests carries a punycode
		// host, so this entry could only ever deny what it appears to allow.
		"münchen.de",
		// An IPv6 address has to arrive as a URL writes it.
		"::1",
	} {
		s := Set{Net: []string{entry}}
		if err := s.Resolve(t.TempDir()); err == nil {
			t.Errorf("%q should be rejected", entry)
		}
	}
}

// TestMetacharactersAreQuoted keeps a host from being read as a pattern. A dot
// is the common case — unquoted, "example.com" would match "exampleXcom".
func TestMetacharactersAreQuoted(t *testing.T) {
	o := applied(t, &Set{Net: []string{"example.com"}})
	if admits(t, o.AllowedModules, "https://exampleXcom/x.pkl") {
		t.Error("the dot in a host must be quoted, not treated as a wildcard")
	}
}
