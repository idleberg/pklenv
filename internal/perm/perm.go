// Package perm expresses what a config is permitted to reach during evaluation.
//
// Pkl's evaluator is gated by two allowlists of URI patterns — one for modules
// (`amends`, `import`) and one for resources (`read`) — plus a root directory
// that file access may not escape. This package is the single place those are
// decided, so the policy can be read, tested and argued about without an
// evaluator in the room.
package perm

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apple/pkl-go/pkl"
	"github.com/spf13/pflag"
)

// Set is the permission state of one pklenv invocation.
//
// The zero value is the default posture: file reads confined to the working
// directory, no network, every environment variable readable. Each field is
// paired with the question "did the user say anything about this?", because for
// all three the answer distinguishes states that a nil slice cannot: a bare
// --allow-net (any host) is not the same as no flag (no host), and an empty
// --allow-env (nothing) is not the same as no flag (everything).
type Set struct {
	// RootDir confines `file:` modules and resources. Empty means unrestricted.
	RootDir string

	// Net lists the hosts, with optional path prefixes, that may be reached.
	Net    []string
	NetAll bool // --allow-net given with no value: any host

	// Env lists the environment variables a config may read.
	Env    []string
	EnvSet bool // --allow-env given: Env is authoritative, including when empty

	// rootDirSet records an explicit --root-dir, so that --root-dir='' can mean
	// "no boundary" rather than "not specified".
	rootDirSet bool

	// The flag set and the slices it parses into. Held because the difference
	// between "flag absent" and "flag given a value" is only knowable after
	// parsing, while pflag hands out its pointers at registration time.
	flags  *pflag.FlagSet
	rawNet *[]string
	rawEnv *[]string
}

// Flag names, exported so the CLI and the hints agree on their spelling.
const (
	FlagWorkingDir = "working-dir"
	FlagRootDir    = "root-dir"
	FlagAllowNet   = "allow-net"
	FlagAllowEnv   = "allow-env"
)

// Register declares the permission flags on f.
//
// --allow-net and --allow-env take an optional value, which pflag spells
// NoOptDefVal. The sentinel is a value no host and no variable name can be, so
// a bare flag is distinguishable from one given a real list.
func Register(f *pflag.FlagSet, s *Set) {
	f.StringVar(&s.RootDir, FlagRootDir, "",
		"confine file reads to this directory (default: the working directory; empty to disable)")

	net := f.StringSlice(FlagAllowNet, nil,
		"hosts a config may fetch modules and resources from, e.g. example.com or example.com/some/path/ (default: none)")
	f.Lookup(FlagAllowNet).NoOptDefVal = sentinelAll

	env := f.StringSlice(FlagAllowEnv, nil,
		"environment variables a config may read (default: all)")
	f.Lookup(FlagAllowEnv).NoOptDefVal = sentinelNone

	s.flags, s.rawNet, s.rawEnv = f, net, env
}

const (
	sentinelAll  = "\x00all"
	sentinelNone = "\x00none"
)

// interpret folds the parsed flag values into the exported fields. Separate
// from Register because a bare --allow-net is only distinguishable from an
// absent one after parsing.
func (s *Set) interpret() {
	if s.flags == nil {
		return // constructed directly, as tests do
	}
	s.rootDirSet = s.flags.Changed(FlagRootDir)

	if s.flags.Changed(FlagAllowNet) {
		s.Net = strip(*s.rawNet, sentinelAll)
		s.NetAll = len(s.Net) == 0
	}
	if s.flags.Changed(FlagAllowEnv) {
		s.EnvSet = true
		s.Env = strip(*s.rawEnv, sentinelNone)
	}
}

func strip(vals []string, sentinel string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v == sentinel || v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

// Resolve finalizes the set against the working directory it was parsed in.
//
// Symlinks are resolved because Pkl resolves them before testing the root
// boundary: an unresolved RootDir would reject files that are genuinely inside
// it. On macOS this is not an edge case — the temporary directory alone is
// /var -> /private/var.
func (s *Set) Resolve(wd string) error {
	s.interpret()

	if !s.rootDirSet {
		s.RootDir = wd
	}
	if s.RootDir != "" {
		abs, err := filepath.Abs(s.RootDir)
		if err != nil {
			return fmt.Errorf("resolving --%s: %w", FlagRootDir, err)
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		s.RootDir = abs
	}

	for _, host := range s.Net {
		if _, err := hostPatterns(host); err != nil {
			return err
		}
	}
	return nil
}

// Apply installs the policy on a set of evaluator options.
//
// It builds the allowlists outright rather than layering onto
// pkl.PreconfiguredOptions, which *appends* its defaults — anything added on
// top of that helper is an addition to "everything is permitted", which reads
// like a restriction and is not one.
func (s *Set) Apply(o *pkl.EvaluatorOptions) {
	// pkl: is the standard library and repl: is how pkl-go submits an
	// expression; neither is a channel to anywhere. file: is listed because the
	// config being evaluated is itself a file: module — RootDir, not this list,
	// is what confines it.
	modules := []string{"pkl:", "repl:", "file:"}

	// prop: is not optional. The standard library reads prop:pkl.outputFormat
	// while rendering, so refusing it fails every evaluation before a config
	// gets a say. It exposes JVM properties pklenv never sets.
	resources := []string{"prop:", "file:"}

	resources = append(resources, envPatterns(s)...)

	// projectpackage: appears only under NetAll, where an unscoped prefix is the
	// point. A named host does not carry it: the scheme resolves through a
	// project's PklProject.deps.json, pklenv never sets ProjectDir, and so the
	// grant would be unreachable as well as unscoped. Verified against pkl
	// 0.32.1 — resolving a projectpackage: import with no project in play fails
	// in the resolver rather than reaching the network. Should pklenv ever grow
	// project support, scope it per host here: those URIs do name one.
	switch {
	case s.NetAll:
		modules = append(modules, "https:", "package:", "projectpackage:")
		resources = append(resources, "https:", "package:", "projectpackage:")
	default:
		for _, host := range s.Net {
			pats, err := hostPatterns(host)
			if err != nil {
				// Resolve rejected these already; a malformed entry surviving to
				// here must not silently widen the allowlist.
				continue
			}
			modules = append(modules, pats...)
			resources = append(resources, pats...)
		}
	}

	o.AllowedModules = modules
	o.AllowedResources = resources
	o.RootDir = s.RootDir
}

// envPatterns renders the environment grant.
//
// Anchored with $ so that a grant of FOO does not also admit FOO_BAR — pkl
// matches these patterns against the beginning of the URI, so without the
// anchor every name is a prefix grant. Verified against pkl 0.32.1.
func envPatterns(s *Set) []string {
	if !s.EnvSet {
		return []string{"env:"}
	}
	out := make([]string, 0, len(s.Env))
	for _, name := range s.Env {
		out = append(out, "env:"+regexp.QuoteMeta(name)+"$")
	}
	return out
}

// hostPatterns renders one --allow-net entry as URI prefix patterns.
//
// Pkl matches patterns against the *beginning* of a URI, which makes the
// trailing slash the load-bearing character here: a pattern of "example.com"
// also matches "example.com.evil.net", because the latter begins with the
// former. Every pattern this produces therefore ends at a path separator.
// Verified: a pattern of ".../a" does admit ".../ab/x.pkl".
//
// The optional port group is there so that naming a host does not accidentally
// exclude the same host on an explicit port, which would refuse a URL the user
// believes they allowed.
func hostPatterns(entry string) ([]string, error) {
	scheme := "https"
	rest := entry

	if s, after, found := strings.Cut(entry, "://"); found {
		switch s {
		case "http", "https":
			scheme, rest = s, after
		default:
			return nil, fmt.Errorf("--%s: %q has an unsupported scheme; use http:// or https://", FlagAllowNet, entry)
		}
	}

	host, path, _ := strings.Cut(rest, "/")
	if host == "" {
		return nil, fmt.Errorf("--%s: %q names no host", FlagAllowNet, entry)
	}
	if strings.ContainsAny(host, "@ \t") {
		return nil, fmt.Errorf("--%s: %q must be a host, optionally followed by a path", FlagAllowNet, entry)
	}

	// An IPv6 literal has to arrive bracketed, as it appears in a URI. Unbracketed
	// it parses as a host that no URI can equal, so it is refused for the same
	// reason as a non-ASCII one: a grant that silently names nothing.
	if !strings.HasPrefix(host, "[") && strings.Count(host, ":") > 1 {
		return nil, fmt.Errorf("--%s: %q must bracket an IPv6 address, as a URL does (e.g. [::1])", FlagAllowNet, entry)
	}

	// A non-ASCII host is rejected rather than matched, because it can never
	// match: Pkl tests these patterns against a URI, whose host is already
	// punycode by the time it gets here. Accepting it would hand back a grant
	// that denies everything it names, which is the worst way for a security
	// flag to fail — silently, and only at the moment it is needed.
	for _, r := range host {
		if r > 127 {
			return nil, fmt.Errorf("--%s: %q must use an ASCII host; convert it to its punycode form (e.g. xn--mnchen-3ya.de)", FlagAllowNet, entry)
		}
	}

	// The host is case-insensitive and reaches the pattern lowercased, so
	// --allow-net=EXAMPLE.com names the same host as example.com. The path is
	// not folded with it: there, case is significant to the server.
	host = strings.ToLower(host)

	// A path prefix is honoured as written; pkl normalizes ".." out of a URI
	// before testing it, so a prefix cannot be escaped by traversal. Verified
	// against pkl 0.32.1.
	suffix := "/"
	if path != "" {
		suffix = "/" + strings.TrimSuffix(path, "/") + "/"
	}

	quoted := regexp.QuoteMeta(host)
	pats := []string{scheme + "://" + quoted + `(:\d+)?` + regexp.QuoteMeta(suffix)}

	// package: resolves over https, so a host allowed for modules is allowed for
	// the packages it serves. Deliberately not a separate flag: nothing in
	// pklenv's workflow uses package: today, and narrowing an existing grant
	// later is backward-compatible in a way that widening one is not.
	if scheme == "https" {
		pats = append(pats, "package://"+quoted+regexp.QuoteMeta(suffix))
	}
	return pats, nil
}
