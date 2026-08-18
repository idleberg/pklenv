// Command pklenv evaluates Pkl environment configs, either injecting the
// result into a child process or writing flat .env files.
package main

import (
	"context"
	"os"

	"github.com/idleberg/pklenv/internal/cli"
)

func main() {
	os.Exit(cli.Main(context.Background(), os.Args[1:]))
}
