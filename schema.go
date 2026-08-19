// Package pklenv exists to embed the repository's own assets into the binary.
//
// It holds no logic. go:embed cannot reach outside the directory of the package
// that declares it, and schema/PklEnv.pkl is authored at the repository root
// where the Pkl tooling and the editor expect to find it, so the directive has
// to live here rather than beside the code that uses it.
package pklenv

import _ "embed"

// Schema is the PklEnv module every pklenv config amends.
//
// Shipping it inside the binary is what lets a config resolve its schema with
// no network access at all, which in turn is what makes denying the network by
// default something a user can live with rather than something they switch off.
// It also means the binary and the schema cannot disagree: the Go-side name
// validation in internal/envfile and the EnvName constraint in this module are
// versions of one rule, and a config evaluated here is checked against the rule
// this binary was built with.
//
//go:embed schema/PklEnv.pkl
var Schema string
