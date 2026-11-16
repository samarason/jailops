package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The rules of a policy are changed with `jailops firewall rule`: no help text, flag description, document, man page or
// example may teach the retired --rule string again. The CHANGELOG is the history and is left out.
func TestNothingTeachesTheRuleString(t *testing.T) {
	root := NewRootCommand(&Env{Getenv: func(string) string { return "" }})
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, text := range []string{c.Short, c.Long, c.Example} {
			if strings.Contains(text, "--rule") {
				t.Errorf("%s: the help mentions --rule", c.CommandPath())
			}
		}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "rule" || strings.Contains(f.Usage, "--rule") {
				t.Errorf("%s: a flag %q teaches --rule", c.CommandPath(), f.Name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)

	for _, dir := range []string{"../../docs", "../../packaging", "../../examples", "../../README.md"} {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr == nil && strings.Contains(string(b), "--rule") {
				t.Errorf("%s mentions --rule", p)
			}
			return nil
		})
	}
}
