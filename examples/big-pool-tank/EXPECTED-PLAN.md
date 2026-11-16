# The first plan

What `jailops-sync plan` prints for this fleet against a host that has nothing yet. The test suite compares it with
the real output on every run, so this page cannot go stale (regenerate with `JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e`).

```
host nas1
  create    Image/freebsd-15
  create    Network/media
  create    Storage/bulk
  create    Project/media
  create    FirewallPolicy/media/closed
  create    FirewallPolicy/media/floor
  create    FirewallPolicy/media/media-server
  create    Volume/media/movies
  create    Volume/media/music
  create    Volume/media/plexdata
  create    Volume/media/work
  create    Jail/media/plex
  create    Jail/media/scratch

projects
  media
    nas1         will be created

13 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged
```
