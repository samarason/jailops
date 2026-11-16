package server

import (
	"context"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// renameRoutes are POST <item>/rename of every kind that can be renamed (extension "rename"): a dry run answers the
// plan at once, a rename answers its operation.
func (s *Server) renameRoutes() []route {
	svc := s.svc
	one := func(base string, fn func(ctx context.Context, name string, o service.RenameOptions) (api.Operation, *api.RenameResult, error)) route {
		return route{method: "POST", pattern: base + "/{name}/rename", h: func(c *rc) error {
			var b api.Rename
			if err := c.decode(&b); err != nil {
				return err
			}
			exp, err := c.expect()
			if err != nil {
				return err
			}
			c.object = base + "/" + c.pathArg("name")
			op, res, err := fn(c.r.Context(), c.pathArg("name"), service.RenameOptions{NewName: b.NewName, DryRun: b.DryRun, Expect: exp})
			if err != nil {
				return err
			}
			if res != nil {
				c.sync(200, res, 0)
				return nil
			}
			c.async(op)
			return nil
		}}
	}
	return []route{
		one("/api/v1/networks", svc.RenameNetwork),
		one("/api/v1/firewall/address-sets", svc.RenameAddressSet),
		one("/api/v1/firewall/policies", svc.RenamePolicy),
		one("/api/v1/profiles", svc.RenameProfile),
		one("/api/v1/jails", svc.RenameJail),
		one("/api/v1/images", svc.RenameImage),
		one("/api/v1/projects", svc.RenameProject),
		one("/api/v1/backup-targets", svc.RenameBackupTarget),
		one("/api/v1/backup-policies", svc.RenameBackupPolicy),
		one("/api/v1/certificates", svc.RenameCertificate),
		one("/api/v1/storage", svc.RenameStorage),
		one("/api/v1/volumes", svc.RenameVolume),
		one("/api/v1/users", svc.RenameUser),
		one("/api/v1/wireguard", svc.RenameWireGuard),
	}
}
