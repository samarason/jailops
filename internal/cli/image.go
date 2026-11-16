package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func imageDesc() *kindDesc[api.Image] {
	d := newDesc("image", "images", api.KindImage,
		func(i *api.Image) *api.ObjectMeta { return &i.Metadata },
		func(i *api.Image) *api.ImageSpec { return &i.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Image] { return c.Images().Resource })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Image] { return c.Images().Resource })
	d.renameLong = renameLong("image", `its datasets and generations on every pool, the jails on it (running
ones too: their image reference, their records and their datasets' properties), the image lists of
projects and the records of its nightly upgrade`)
	d.head = []string{"NAME", "OS", "RELEASE", "ARCH", "GENERATIONS", "ALIASES"}
	d.row = func(_ time.Time, i api.Image) []string {
		return []string{i.Metadata.Name, string(i.Spec.OS), i.Spec.Release, i.Spec.Arch,
			strconv.Itoa(len(i.Status.Generations)), joinOrDash(i.Spec.Aliases)}
	}
	d.show = func(a *app, i api.Image) error { return a.showImage(i) }
	d.emptyHintFrom = func(ctx context.Context, c *sdk.Client) string {
		release := "15.1-RELEASE"
		if info, err := c.Info(ctx); err == nil && api.ImageNameForRelease(info.Environment.KernelVersion) != "" {
			release = api.BaseRelease(info.Environment.KernelVersion)
		}
		name := api.ImageNameForRelease(release)
		return "jailops image create " + name + " --release " + release + ", then jailops image build " + name
	}
	return &d
}

// imageRefs completes an image reference: NAME@ALIAS for each alias of an image, and the bare NAME.
func imageRefs(ctx context.Context, c *sdk.Client) ([]string, error) {
	imgs, err := collect(c.Images().List(ctx))
	var out []string
	for _, i := range imgs {
		aliases := slices.Clone(i.Spec.Aliases)
		for _, al := range sortedKeys(i.Status.Aliases) {
			if !slices.Contains(aliases, al) {
				aliases = append(aliases, al)
			}
		}
		for _, al := range aliases {
			out = append(out, i.Metadata.Name+"@"+al)
		}
		out = append(out, i.Metadata.Name)
	}
	return out, err
}

// parseGeneration reads a generation written as gN or N, or as IMAGE#gN when
// image names the image it must belong to; what names the flag or argument
// for the error. It returns the number.
func parseGeneration(what, s, image string) (int, error) {
	ref := s
	if img, g, ok := strings.Cut(s, "#"); ok {
		if image != "" && img != image {
			return 0, usagef("%s: %q belongs to image %s, not %s", what, s, img, image)
		}
		ref = g
	}
	n, err := strconv.Atoi(strings.TrimPrefix(ref, "g"))
	if err != nil || n < 1 {
		return 0, usagef("%s must be a generation such as g2, not %q", what, s)
	}
	return n, nil
}

// generationNames lists the generations of an image as gN, for completion.
func generationNames(ctx context.Context, c *sdk.Client, image string) ([]string, error) {
	gens, err := collect(c.Images().Generations(ctx, image))
	var n []string
	for _, g := range gens {
		n = append(n, fmt.Sprintf("g%d", g.Number))
	}
	return n, err
}

// completeGenerations completes a generation of the image named first.
func (a *app) completeGenerations() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		return generationNames(ctx, c, args[0])
	})
}

// completeAliases completes an alias of the image named first.
func (a *app) completeAliases() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		img, err := c.Images().Get(ctx, args[0])
		if err != nil {
			return nil, err
		}
		return sortedKeys(img.Status.Aliases), nil
	})
}

func (a *app) imageCmd() *cobra.Command {
	d := imageDesc()
	ic := group("image", "Manage images and their generations",
		`An image is one release, such as freebsd-15-1 for FreeBSD 15.1, built from
packages. Every build adds an immutable generation (g1, g2, ...): the patch
levels of the release. A jail's root is a clone of one generation; a jail that
names the image by its name follows its newest generation, and 'jailops image
upgrade' builds the next one and moves the jails to it. A new release is a new
image. Aliases name a generation by another name, for advanced use.`,
		`jailops image list
jailops image build freebsd-15-1
jailops image upgrade freebsd-15-1
jailops image generation list freebsd-15-1`, "images")
	crudCommands(a, ic, d, `Define an image. The definition says where the base comes from; 'jailops image
build' then produces its first generation. Without --arch the image is built for
the architecture of the server. A new image name has at most 32 characters.`,
		`jailops image create freebsd-15-1 --release 15.1-RELEASE
jailops image create freebsd-15-1-arm --release 15.1-RELEASE --arch arm64
jailops image create -f freebsd-15-1.yaml`,
		func(cmd *cobra.Command) func(string) (api.Image, error) {
			var os_, release, arch, stype, repo, keys, comment, upgradeAt string
			var autoUpgrade, upgradePackages bool
			var sets, aliases []string
			var keepLast, keepDays int
			f := cmd.Flags()
			f.StringVar(&comment, "comment", "", "what the image is for")
			f.StringVar(&os_, "os", "freebsd", "guest operating system: freebsd or linux")
			f.StringVar(&release, "release", "", "release, for example 15.1-RELEASE (required without -f)")
			f.StringVar(&arch, "arch", "", "architecture: amd64 or arm64 (default: the server's)")
			f.StringVar(&stype, "source-type", "pkgbase", "how the base is built: pkgbase, minirootfs or debootstrap")
			enumFlag(cmd, "os", string(api.OSFreeBSD), string(api.OSLinux))
			enumFlag(cmd, "arch", "amd64", "arm64")
			enumFlag(cmd, "source-type", "pkgbase", "minirootfs", "debootstrap")
			f.StringVar(&repo, "repo", "", "package repository or rootfs mirror")
			f.StringVar(&keys, "keys", "", "keyring or key directory that checks the base's signature (required for debootstrap)")
			f.StringArrayVar(&sets, "package-set", nil, "package set to install (repeatable)")
			f.StringArrayVar(&aliases, "alias", nil, "movable alias such as stable (repeatable)")
			f.IntVar(&keepLast, "keep-last", 0, "always keep this many generations")
			f.IntVar(&keepDays, "keep-days", 0, "keep unused generations this many days")
			f.BoolVar(&autoUpgrade, "auto-upgrade", false, "upgrade the image every night: build the next generation (the patch updates of the release) and move its thin jails to it one at a time, with a health check and an automatic rollback")
			f.StringVar(&upgradeAt, "upgrade-at", api.DefaultAutoUpgradeAt, "time of day of the nightly upgrade, HH:MM in the host's time zone")
			f.BoolVar(&upgradePackages, "upgrade-packages", true, "with --auto-upgrade, upgrade the packages inside the running jails of the image too")
			return func(name string) (api.Image, error) {
				if release == "" && !a.partial {
					return api.Image{}, usagef("--release is required (or use -f FILE)")
				}
				if arch == "" && !a.partial { // set builds from the flags given and has the stored architecture
					var err error
					if arch, err = a.serverArch(cmd.Context()); err != nil {
						return api.Image{}, err
					}
				}
				spec := api.ImageSpec{
					Comment: comment, OS: api.OS(os_), Release: release, Arch: arch,
					Source:    api.ImageSource{Type: stype, Repo: repo, Keys: keys, Sets: sets},
					Aliases:   aliases,
					Retention: api.ImageRetention{KeepLast: keepLast, KeepDays: keepDays},
				}
				if autoUpgrade || cmd.Flags().Changed("auto-upgrade") || cmd.Flags().Changed("upgrade-at") || cmd.Flags().Changed("upgrade-packages") {
					spec.AutoUpgrade = &api.ImageAutoUpgrade{Enabled: autoUpgrade, At: upgradeAt, Packages: upgradePackages}
				}
				return api.Image{Metadata: api.ObjectMeta{Name: name}, Spec: spec}, nil
			}
		})
	for _, c := range ic.Commands() {
		if c.Name() == "delete" {
			c.Long = "Delete one or more images with all their generations and aliases. The server refuses, naming the jails, while a jail uses any generation.\nThe command asks for confirmation unless -y is given."
		}
	}
	ic.AddCommand(a.imageBuild(d), a.imageUpgrade(d), a.imageAlias(d), a.imageGeneration(d))
	return ic
}

// serverArch asks the server for its architecture, the default of a new
// image's --arch.
func (a *app) serverArch(ctx context.Context) (string, error) {
	c, err := a.connect(ctx)
	if err != nil {
		return "", err
	}
	info, err := c.Info(ctx)
	if err != nil {
		return "", err
	}
	if info.Environment.Arch == "" {
		return "", &hintError{err: errors.New("the server does not report its architecture"), hint: "pass --arch amd64 or --arch arm64"}
	}
	return info.Environment.Arch, nil
}

func (a *app) imageUpgrade(d *kindDesc[api.Image]) *cobra.Command {
	var noJails bool
	cmd := &cobra.Command{
		Use:   "upgrade IMAGE",
		Short: "Build the next generation and move the jails that use the image to it",
		Long: `Upgrade an image: build the next generation from its newest one (its packages
upgraded), then move every thin jail that uses the image to it, one at a time,
through the steps of 'jailops jail upgrade' (snapshot, new root, /etc merge,
swap, health check, root rollback on failure), with a record in each jail's
update history. The first jail that fails or needs a human stops the operation;
the jails after it are not attempted. When the package set did not change, no
generation is kept and no jail is touched.

Jails of every project are moved unless --project names one (the flag only; the
current project of the remote does not narrow an image upgrade). Thick jails,
Linux jails, jails with another update strategy and jails pinned to a
generation are skipped and listed. A stopped jail is moved too: it is started for
the health check and stopped again.

--no-jails builds the generation only. --dry-run plans the build and lists the
jails that would move; nothing changes. The build can take minutes; the command
waits unless --no-wait is given. The exit status is 1 when a jail failed.`,
		Example: `jailops image upgrade freebsd-15-1 --dry-run
jailops image upgrade freebsd-15-1
jailops image upgrade freebsd-15-1 --project shop
jailops image upgrade freebsd-15-1 --no-jails`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, image := cmd.Context(), args[0]
			u := api.ImageUpgrade{NoJails: noJails, Project: a.project, DryRun: a.dryRun}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := handle(c.Images().Upgrade(ctx, image, u))
			if err != nil {
				return err
			}
			if !a.waiting() && !a.dryRun {
				return a.finishOp(ctx, h, "image", image, "upgrading", nil)
			}
			v, _, err := a.await(ctx, h)
			if err != nil {
				return err
			}
			res, _ := v.(api.ImageUpgradeResult)
			return a.emitImageUpgrade(image, res)
		},
	}
	cmd.Flags().BoolVar(&noJails, "no-jails", false, "build the generation only; move no jail")
	return cmd
}

// emitImageUpgrade prints the result of an image upgrade: what the build did,
// then one line per jail. A failed jail makes the exit status 1.
func (a *app) emitImageUpgrade(image string, res api.ImageUpgradeResult) error {
	if a.format == fmtTable {
		switch {
		case res.Unchanged && !anyJailMoved(res):
			fprintf(a.env.Stdout, "image/%s unchanged: %s already has the current package set; nothing to upgrade\n", image, res.From)
		case res.Unchanged:
			fprintf(a.env.Stdout, "image/%s: %s already has the current package set; the jails that were behind moved to it\n", image, res.From)
		case res.DryRun:
			n := 0
			for _, j := range res.Jails {
				if j.Status == api.ImageUpgradePlanned {
					n++
				}
			}
			fprintf(a.env.Stdout, "dry-run: would build the next generation of %s from %s and move %d of %d jails\n", image, res.From, n, len(res.Jails))
		case res.Generation != nil:
			fprintf(a.env.Stdout, "generation/%s built from %s\n", res.Generation.Name, res.From)
		}
		if len(res.Jails) == 0 {
			fprintf(a.env.Stdout, "no jail uses %s\n", image)
			return nil
		}
	}
	err := a.emit(res, func(col int, v string) string {
		if col != 2 {
			return ""
		}
		switch v {
		case api.ImageUpgradeUpgraded:
			return "32"
		case api.ImageUpgradeFailed:
			return "31"
		case api.ImageUpgradeNotAttempted:
			return "33"
		}
		return ""
	}, func() ([]string, [][]string) {
		if len(res.Jails) == 0 {
			return nil, nil
		}
		var rows [][]string
		for _, j := range res.Jails {
			rows = append(rows, []string{j.Jail, j.Project, j.Status, dash(j.From), dash(j.To), dash(j.Reason)})
		}
		return []string{"JAIL", "PROJECT", "STATUS", "FROM", "TO", "REASON"}, rows
	}, func() []string {
		var n []string
		for _, j := range res.Jails {
			n = append(n, j.Jail)
		}
		return n
	})
	if err != nil {
		return err
	}
	for _, j := range res.Jails {
		if j.Status == api.ImageUpgradeFailed {
			return &hintError{err: fmt.Errorf("jail %s failed; the jails after it were not attempted", j.Jail),
				hint: "'jailops update history " + j.Jail + " --project " + j.Project + "' shows what happened; run the upgrade again once it is resolved"}
		}
	}
	return nil
}

func (a *app) imageGenerationList(d *kindDesc[api.Image]) *cobra.Command {
	return &cobra.Command{
		Use:               "list IMAGE",
		Short:             "List the generations of an image",
		Long:              "List the generations of an image with the jails that use each one. A generation can be deleted only when no jail uses it.\nThe number (g1, g2, ...) is the JailOps generation counter of the image; FREEBSD is the FreeBSD version its base\npackages were built from (15.1-RELEASE-p6: release 15.1, patch level 6), or - for a generation built before JailOps\nrecorded it.",
		Example:           "jailops image generation list freebsd-15-1\njailops image generation list freebsd-15-1 -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			gens, err := collect(c.Images().Generations(cmd.Context(), args[0]))
			if err != nil {
				return err
			}
			return a.emit(nonNil(gens), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, g := range gens {
					m := g.Manifest
					if len(m) > 19 {
						m = m[:19]
					}
					rows = append(rows, []string{g.Name, strconv.Itoa(g.Number), dash(parentName(g.Parent)), dash(g.FreeBSDVersion), strconv.Itoa(g.Packages),
						dash(m), age(a.env.Now(), g.CreatedAt), joinOrDash(g.Refs)})
				}
				return []string{"NAME", "NUMBER", "PARENT", "FREEBSD", "PACKAGES", "MANIFEST", "AGE", "USED BY"}, rows
			}, func() []string {
				var n []string
				for _, g := range gens {
					n = append(n, g.Name)
				}
				return n
			})
		},
	}
}

func parentName(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("g%d", n)
}

func (a *app) imageBuild(d *kindDesc[api.Image]) *cobra.Command {
	var from string
	cmd := &cobra.Command{
		Use:   "build IMAGE",
		Short: "Build the next generation of an image",
		Long: `Build the next generation of an image from its source, or from an earlier
generation with --from-generation (which upgrades that generation's packages). The build
can take minutes; the command waits unless --no-wait is given.

--dry-run asks the server to plan the build without keeping the result.`,
		Example:           "jailops image build freebsd-15-1\njailops image build freebsd-15-1 --from-generation g2 --dry-run",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			b := api.ImageBuild{DryRun: a.dryRun}
			if from != "" {
				n, err := parseGeneration("--from-generation", from, args[0])
				if err != nil {
					return err
				}
				b.FromGeneration = n
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Images().Build(cmd.Context(), args[0], b))
			if err != nil {
				return err
			}
			if a.dryRun {
				v, _, err := a.await(cmd.Context(), h)
				if err != nil {
					return err
				}
				g, _ := v.(api.ImageGeneration)
				return a.preview(fmt.Sprintf("build %s (%d packages)", dash(g.Name), g.Packages), b)
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "image", args[0], "built", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			g, _ := v.(api.ImageGeneration)
			return a.emitOne(g, "generation", g.Name, "built")
		},
	}
	cmd.Flags().StringVar(&from, "from-generation", "", "build from this earlier generation, gN")
	_ = cmd.RegisterFlagCompletionFunc("from-generation", a.completeGenerations())
	return cmd
}

func (a *app) imageAlias(d *kindDesc[api.Image]) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "Point a movable alias of an image at a generation, or remove it",
		Long: `Aliases such as "stable" or "latest" name a generation of an image. Jails that
reference IMAGE@ALIAS follow the generation the alias points to. A build moves the
aliases of the image to the new generation; 'alias add' pins one to any generation.`,
		Example: "jailops image alias add freebsd-15-1 stable --generation g2\njailops image alias remove freebsd-15-1 old",
	}
	cmd.AddCommand(a.imageAliasAdd(d), a.imageAliasRemove(d))
	return cmd
}

func (a *app) imageAliasAdd(d *kindDesc[api.Image]) *cobra.Command {
	var gen string
	cmd := &cobra.Command{
		Use:   "add IMAGE ALIAS",
		Short: "Point an alias at a generation (the newest when omitted)",
		Long: `Create the alias or move it to the generation --generation names (gN, or the number N). Without
--generation it points at the newest generation. The alias is also recorded in the
image spec, so later builds keep moving it.`,
		Example:           "jailops image alias add freebsd-15-1 stable --generation g2\njailops image alias add freebsd-15-1 latest",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeArgs(completeKind(a, d), a.completeAliases()),
		RunE: func(cmd *cobra.Command, args []string) error {
			n := 0
			if gen != "" {
				var err error
				if n, err = parseGeneration("--generation", gen, args[0]); err != nil {
					return err
				}
			}
			target := "the newest generation"
			if n > 0 {
				target = fmt.Sprintf("generation g%d", n)
			}
			if ok, err := a.dry(fmt.Sprintf("point alias %s of image %s at %s", args[1], args[0], target), nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			img, err := c.Images().SetAlias(cmd.Context(), args[0], args[1], n)
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "image", args[0], fmt.Sprintf("alias %s set to g%d", args[1], img.Status.Aliases[args[1]]), nil)
		},
	}
	cmd.Flags().StringVar(&gen, "generation", "", "generation the alias points at, gN or N (default: the newest)")
	_ = cmd.RegisterFlagCompletionFunc("generation", func(c *cobra.Command, args []string, p string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return a.completeGenerations()(c, args[:1], p)
	})
	return cmd
}

func (a *app) imageAliasRemove(d *kindDesc[api.Image]) *cobra.Command {
	return &cobra.Command{
		Use:   "remove IMAGE ALIAS",
		Short: "Remove an alias of an image",
		Long: `Remove the alias from the image and from its spec, so a later build does not bring
it back. Jails that reference IMAGE@ALIAS can no longer resolve it.`,
		Example:           "jailops image alias remove freebsd-15-1 old",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeArgs(completeKind(a, d), a.completeAliases()),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry(fmt.Sprintf("remove alias %s of image %s", args[1], args[0]), nil); ok || err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Remove alias %s of image %s?", args[1], args[0])); err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			if _, err := c.Images().DeleteAlias(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "image", args[0], "alias "+args[1]+" removed", nil)
		},
	}
}

func (a *app) imageGenerationDelete(d *kindDesc[api.Image]) *cobra.Command {
	return &cobra.Command{
		Use:               "delete IMAGE GENERATION",
		Short:             "Delete a generation of an image that no jail uses",
		Long:              "Delete one generation (gN, or the number N) of an image. The server refuses (image_in_use) while a jail uses it. Aliases that pointed at it move to the next newest remaining generation, or are removed when none remains.",
		Example:           "jailops image generation delete freebsd-15-1 g1",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeArgs(completeKind(a, d), a.completeGenerations()),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := parseGeneration("GENERATION", args[1], args[0])
			if err != nil {
				return err
			}
			label := fmt.Sprintf("%s#g%d", args[0], n)
			if ok, err := a.dry("delete generation "+label, nil); ok || err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Delete generation %s?", label)); err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Images().DeleteGeneration(cmd.Context(), args[0], n))
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), h, "generation", label, "deleted", nil)
		},
	}
}

// anyJailMoved says whether an image upgrade moved a jail.
func anyJailMoved(res api.ImageUpgradeResult) bool {
	for _, j := range res.Jails {
		if j.Status == api.ImageUpgradeUpgraded {
			return true
		}
	}
	return false
}

// imageGeneration is the group of the generations of an image: list and delete.
func (a *app) imageGeneration(d *kindDesc[api.Image]) *cobra.Command {
	gc := group("generation", "List and delete the generations of an image",
		"Every build of an image is a generation (g1, g2, ...). A generation can be deleted when no jail uses it.",
		"jailops image generation list freebsd-15-1\njailops image generation delete freebsd-15-1 g1")
	gc.AddCommand(a.imageGenerationList(d), a.imageGenerationDelete(d))
	return gc
}
