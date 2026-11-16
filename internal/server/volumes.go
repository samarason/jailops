package server

import (
	"context"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// ---- volumes ----

func (s *Server) volumeRoutes() []route {
	svc := s.svc
	vr := resource[api.Volume]{base: "/api/v1/volumes", param: "name",
		list: svc.ListVolumes,
		get:  func(ctx context.Context, k string) (api.Volume, error) { return svc.GetVolume(ctx, k) },
		put:  svc.UpdateVolume, patch: svc.PatchVolume,
		gen: func(v api.Volume) int64 { return v.Metadata.Generation }, name: func(v api.Volume) string { return v.Metadata.Name },
	}.routes()
	// The passphrase of an encrypted volume is in the body of these requests and nowhere else.
	return append(vr,
		route{method: "POST", pattern: "/api/v1/volumes", h: func(c *rc) error {
			var in api.VolumeCreate
			if err := c.decode(&in); err != nil {
				return err
			}
			c.object = "/api/v1/volumes/" + in.Metadata.Name
			op, err := svc.CreateVolume(c.r.Context(), in)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/volumes/{name}", h: func(c *rc) error {
			op, err := svc.DeleteVolume(c.r.Context(), c.pathArg("name"), service.AnyGeneration)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/volumes/{name}/unlock", h: func(c *rc) error {
			var u api.VolumeUnlock
			if err := c.decode(&u); err != nil {
				return err
			}
			op, err := svc.UnlockVolume(c.r.Context(), c.pathArg("name"), u)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/volumes/{name}/lock", h: func(c *rc) error {
			op, err := svc.LockVolume(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/volumes/{name}/passphrase", h: func(c *rc) error {
			var pc api.VolumePassphraseChange
			if err := c.decode(&pc); err != nil {
				return err
			}
			op, err := svc.ChangeVolumePassphrase(c.r.Context(), c.pathArg("name"), pc)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/volumes/{name}/snapshots", h: func(c *rc) error {
			v, err := svc.ListVolumeSnapshots(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/volumes/{name}/snapshots", h: func(c *rc) error {
			var sn api.VolumeSnapshot
			if err := c.decodeOptional(&sn); err != nil {
				return err
			}
			op, err := svc.CreateVolumeSnapshot(c.r.Context(), c.pathArg("name"), sn)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/volumes/{name}/snapshots/{snapshot}", h: func(c *rc) error {
			op, err := svc.DeleteVolumeSnapshot(c.r.Context(), c.pathArg("name"), c.pathArg("snapshot"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/volumes/{name}/rollback", h: func(c *rc) error {
			var rb api.VolumeRollback
			if err := c.decode(&rb); err != nil {
				return err
			}
			op, err := svc.RollbackVolume(c.r.Context(), c.pathArg("name"), rb)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
	)
}
