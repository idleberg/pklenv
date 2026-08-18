package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDescribe(t *testing.T) {
	tests := []struct {
		path    string
		wantEnv string
		wantTgt string
		wantErr bool
	}{
		{path: "env.pkl", wantEnv: "", wantTgt: ".env"},
		{path: "env.local.pkl", wantEnv: "local", wantTgt: ".env.local"},
		{path: "env.production.pkl", wantEnv: "production", wantTgt: ".env.production"},
		// The convention says this should amend env.production.pkl, but the
		// filename carries no hierarchy as far as pklenv is concerned.
		{path: "env.production.local.pkl", wantEnv: "production.local", wantTgt: ".env.production.local"},
		{path: "config/env.staging.pkl", wantEnv: "staging", wantTgt: ".env.staging"},

		{path: "notenv.pkl", wantErr: true},
		{path: "env.pkl.bak", wantErr: true},
		{path: "env..pkl", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := Describe(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Describe(%q) = %+v, want an error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Environment != tt.wantEnv {
				t.Errorf("Environment = %q, want %q", got.Environment, tt.wantEnv)
			}
			if got.Target != tt.wantTgt {
				t.Errorf("Target = %q, want %q", got.Target, tt.wantTgt)
			}
		})
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"env.pkl",
		"env.local.pkl",
		"env.production.pkl",
		"notenv.pkl",    // not a pklenv config
		"env.txt",       // not Pkl
		"README.md",     // unrelated
		"envelope.pkl",  // no dot after "env"
		"other.env.pkl", // does not start with env.
	} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "env.dir.pkl"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"env.local.pkl", "env.pkl", "env.production.pkl"}
	if len(got) != len(want) {
		t.Fatalf("got %d sources %v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if base := filepath.Base(got[i].Path); base != w {
			t.Errorf("position %d = %q, want %q", i, base, w)
		}
	}
}

func TestDiscoverMissingDir(t *testing.T) {
	if _, err := Discover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}
