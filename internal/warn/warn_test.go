package warn

import (
	"testing"

	"github.com/idleberg/pklenv/internal/redact"
)

func TestScanReportsOnlyUndeclared(t *testing.T) {
	decisions := map[string]redact.Decision{
		"API_TOKEN":     redact.Undeclared, // looks sensitive, nothing covers it
		"DB_PASSWORD":   redact.Redacted,   // already handled
		"LEGACY_SECRET": redact.Waived,     // somebody looked and said no
		"NODE_ENV":      redact.Undeclared, // undeclared but unremarkable
	}

	got := Scan(decisions, nil)
	if len(got) != 1 {
		t.Fatalf("got %d findings (%v), want 1", len(got), got)
	}
	if got[0].Name != "API_TOKEN" {
		t.Errorf("got %q, want API_TOKEN", got[0].Name)
	}
	if got[0].Pattern != "TOKEN" {
		t.Errorf("got pattern %q, want TOKEN", got[0].Pattern)
	}
}

// The whole point of keeping redact=false as the suppressor: an explicit
// decision, recorded in the repo where a reviewer sees it, silences the noise.
func TestScanRespectsWaiver(t *testing.T) {
	for _, d := range []redact.Decision{redact.Redacted, redact.Waived} {
		got := Scan(map[string]redact.Decision{"GITHUB_TOKEN": d}, nil)
		if len(got) != 0 {
			t.Errorf("decision %v: got %v, want no findings", d, got)
		}
	}
}

func TestScanMatching(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"API_TOKEN", true},
		{"DB_PASSWORD", true},
		{"MYSQL_PASSWD", true},
		{"AWS_CREDENTIAL_FILE", true},
		{"SSH_PRIVATE_KEY", true},
		{"STRIPE_API_KEY", true},
		{"CLIENT_SECRET", true},
		{"database_password", true}, // heuristics are case-insensitive
		{"DATABASE_PASSWORD_FILE", true},

		// Deliberately not flagged — a bare KEY pattern would make the warning
		// worthless within a day.
		{"SORT_KEY", false},
		{"PUBLIC_KEY", false},
		{"CACHE_KEY_PREFIX", false},
		{"KEYBOARD_SHORTCUTS", false},
		{"NODE_ENV", false},
		{"PORT", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scan(map[string]redact.Decision{tt.name: redact.Undeclared}, nil)
			if (len(got) > 0) != tt.want {
				t.Errorf("Scan(%q) flagged=%v, want %v", tt.name, len(got) > 0, tt.want)
			}
		})
	}
}

func TestScanIsSorted(t *testing.T) {
	got := Scan(map[string]redact.Decision{
		"Z_TOKEN": redact.Undeclared,
		"A_TOKEN": redact.Undeclared,
		"M_TOKEN": redact.Undeclared,
	}, nil)

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	for i, want := range []string{"A_TOKEN", "M_TOKEN", "Z_TOKEN"} {
		if got[i].Name != want {
			t.Errorf("position %d = %q, want %q", i, got[i].Name, want)
		}
	}
}

func TestScanCustomPatterns(t *testing.T) {
	got := Scan(map[string]redact.Decision{
		"INTERNAL_PEPPER": redact.Undeclared,
		"API_TOKEN":       redact.Undeclared,
	}, []string{"PEPPER"})

	if len(got) != 1 || got[0].Name != "INTERNAL_PEPPER" {
		t.Errorf("got %v, want only INTERNAL_PEPPER — custom patterns replace the defaults", got)
	}
}
