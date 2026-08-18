package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Source is a discovered config file and the .env file it corresponds to.
type Source struct {
	// Path is the .pkl file.
	Path string

	// Environment is the segment between "env." and ".pkl", empty for env.pkl.
	Environment string

	// Target is the dotenv-convention filename this evaluates to.
	Target string
}

// Discover finds every pklenv config in dir.
//
// Discovery is a plain glob and nothing more: env.pkl plus anything matching
// env.*.pkl. No hierarchy is inferred from the filename and no files are
// combined. Merging happens only through a file's own explicit `amends`
// declaration, which Pkl's evaluator resolves — pklenv evaluates each
// discovered file independently and never joins two of them itself.
//
// The naming/amends correspondence (env.production.local.pkl should amend
// env.production.pkl) is a convention this does not enforce.
func Discover(dir string) ([]Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var out []Source
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".pkl") {
			continue
		}
		if name != "env.pkl" && !strings.HasPrefix(name, "env.") {
			continue
		}
		src, ok := describe(filepath.Join(dir, name))
		if !ok {
			continue
		}
		out = append(out, src)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Describe maps a config path to its dotenv target.
//
//	env.pkl            -> .env
//	env.local.pkl      -> .env.local
//	env.production.pkl -> .env.production
func Describe(path string) (Source, error) {
	src, ok := describe(path)
	if !ok {
		return Source{}, fmt.Errorf(
			"%s is not a pklenv config: expected env.pkl or env.<environment>.pkl",
			filepath.Base(path))
	}
	return src, nil
}

func describe(path string) (Source, bool) {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".pkl") {
		return Source{}, false
	}
	stem := strings.TrimSuffix(base, ".pkl")

	if stem == "env" {
		return Source{Path: path, Target: ".env"}, true
	}
	env, ok := strings.CutPrefix(stem, "env.")
	if !ok || env == "" {
		return Source{}, false
	}
	return Source{Path: path, Environment: env, Target: ".env." + env}, true
}
