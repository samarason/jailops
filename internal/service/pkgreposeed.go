package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"jailops.net/jailops/internal/apps"
)

// hostPkgDir is where the host keeps the configuration of its package repositories (docs/install.md).
var hostPkgDir = "/usr/local/etc/pkg"

var rePubkeyLine = regexp.MustCompile(`(?m)^\s*pubkey\s*:\s*"([^"\n]+)"`)

// seedJailopsRepo puts the configuration of the JailOps package repository, and its public key, into the root of a
// jail that has just had packages from it installed. A running jail gets its packages updated with pkg -j (pkg enters
// the jail, so nothing of the host's root writes into a root that runs), which reads the jail's own configuration:
// without this the packages of the repository would never find a newer version. The jail is stopped and has never
// run, and the files are the host's own, so a jail can trust the repository the host trusts and no other.
func (s *Service) seedJailopsRepo(ctx context.Context, root string) error {
	conf, err := os.ReadFile(path.Join(hostPkgDir, "repos", apps.JailopsRepo+".conf"))
	if errors.Is(err, os.ErrNotExist) {
		return nil // the installation named the repository, so a host without it failed before; nothing to copy
	}
	if err != nil {
		return err
	}
	files := map[string][]byte{path.Join(hostPkgDir, "repos", apps.JailopsRepo+".conf"): conf}
	if m := rePubkeyLine.FindSubmatch(conf); m != nil {
		key := path.Clean(string(m[1]))
		if !strings.HasPrefix(key, hostPkgDir+"/") {
			return fmt.Errorf("the key %s of the %s repository is not below %s: copy it into the jail by hand", key, apps.JailopsRepo, hostPkgDir)
		}
		b, err := os.ReadFile(key)
		if err != nil {
			return fmt.Errorf("the key of the %s repository: %w", apps.JailopsRepo, err)
		}
		files[key] = b
	}
	for p, b := range files {
		if err := s.d.Files.MkdirAll(ctx, root+path.Dir(p)); err != nil {
			return err
		}
		if err := s.d.Files.WriteAtomic(ctx, root+p, b); err != nil {
			return err
		}
	}
	return nil
}
