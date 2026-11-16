package cli

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestEveryFlagAndArgumentIsClassified walks the whole command tree. A flag that is not a switch or a number must
// complete something (a server object, a file, a directory, one of a few values) or be listed below as free text with
// the reason; a command with a positional argument must complete it or be listed as naming something new. A new flag
// or command that is neither fails here, so completion cannot be forgotten.
func TestEveryFlagAndArgumentIsClassified(t *testing.T) {
	root := NewRootCommand(&Env{Getenv: func(string) string { return "" }})
	gone, cancel := context.WithCancel(context.Background())
	cancel()

	freeUsed := map[string]bool{}
	typedUsed := map[string]bool{}
	var problems []string

	check := func(c *cobra.Command, f *pflag.Flag) {
		path := strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
		switch f.Value.Type() {
		case "bool", "count":
			return // a switch: nothing follows it
		}
		fn, ok := c.GetFlagCompletionFunc(f.Name)
		if !ok {
			problems = append(problems, c.CommandPath()+" --"+f.Name+": no completion; list it in freeTextFlags with the reason if its value is typed")
			return
		}
		for _, key := range []string{path + " --" + f.Name, f.Name} {
			if _, listed := freeTextFlags[key]; listed {
				freeUsed[key] = true
				// text that is typed completes nothing and never the files of the directory
				if _, dir := fn(c, nil, ""); dir&cobra.ShellCompDirectiveNoFileComp == 0 {
					problems = append(problems, c.CommandPath()+" --"+f.Name+": free text completes the files of the directory")
				}
			}
		}
		if isNumberFlag(f) {
			if _, dir := fn(c, nil, ""); dir&cobra.ShellCompDirectiveNoFileComp == 0 {
				problems = append(problems, c.CommandPath()+" --"+f.Name+": a number completes the files of the directory")
			}
		}
	}

	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		c.SetContext(gone) // no server to ask: the completions that need one return at once
		c.NonInheritedFlags().VisitAll(func(f *pflag.Flag) { check(c, f) })
		if c == root {
			c.PersistentFlags().VisitAll(func(f *pflag.Flag) { check(c, f) })
		}
		if c.Runnable() && len(c.Commands()) == 0 {
			path := strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
			switch {
			case c.ValidArgsFunction == nil:
				problems = append(problems, path+": no completion function (finishCompletion should have set one)")
			case c.Annotations[typedAnnotation] != "":
				typedUsed[path] = true
				if _, ok := typedArguments[path]; !ok {
					problems = append(problems, path+": takes "+c.Use+" but completes nothing and is not listed in typedArguments")
				}
			}
			if c.ValidArgsFunction != nil {
				// at every position the argument is a name, a value or a path: the files of the directory are offered
				// only where the argument is a path (pathArguments)
				for n := 0; n < 4; n++ {
					args := make([]string, n)
					for i := range args {
						args[i] = "x"
					}
					vals, dir := c.ValidArgsFunction(c, args, "")
					if dir&cobra.ShellCompDirectiveNoFileComp != 0 {
						continue
					}
					if _, ok := pathArguments[path]; !ok {
						problems = append(problems, path+": argument "+itoa(n+1)+" falls back to the files of the directory ("+itoa(int(dir))+", "+itoa(len(vals))+" candidates)")
					}
				}
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)

	for key := range freeTextFlags {
		if !freeUsed[key] {
			problems = append(problems, "freeTextFlags has "+key+" which matches no flag: remove it")
		}
	}
	for path := range typedArguments {
		if !typedUsed[path] {
			problems = append(problems, "typedArguments has "+path+" which is not a command with a typed argument: remove it")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// typedArguments are the commands with a positional argument that names something that does not exist yet (or a
// secret pasted from elsewhere), so there is nothing to complete: they say so in one line (ActiveHelp).
var typedArguments = map[string]string{
	"backup policy create":        "the name of a new policy",
	"backup target create":        "the name of a new target",
	"cert create":                 "the name of a new certificate",
	"create":                      "the name of a new jail",
	"firewall address-set create": "the name of a new address set",
	"firewall policy create":      "the name of a new policy",
	"host create":                 "the name of a new host",
	"image create":                "the name of a new image",
	"jail create":                 "the name of a new jail",
	"network create":              "the name of a new network",
	"profile create":              "the name of a new profile",
	"project create":              "the name of a new project",
	"storage create":              "the name of a new storage",
	"token create":                "the name of a new token",
	"user create":                 "the name of a new user",
	"volume create":               "the name of a new volume",
	"wireguard create":            "the name of a new interface",
}

// pathArguments are the commands whose positional argument is a path, so that the files of the directory are right.
var pathArguments = map[string]string{
	"app validate": "the paths of app definitions",
}

func itoa(n int) string { return strconv.Itoa(n) }
