# The first plan

What `jailops-sync plan` prints for this fleet against a host that has nothing yet. The test suite compares it with
the real output on every run, so this page cannot go stale (regenerate with `JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e`).

```
host web1
  create    Image/freebsd-15
  create    Network/db
  create    Network/web
  create    Storage/fast
  create    Project/db
  create    Project/web
  create    FirewallPolicy/db/base
  create    FirewallPolicy/web/base
  create    BackupTarget/vault
  create    Volume/db/postgres-data
  create    Jail/db/postgres
  create    Jail/web/blog
host web2
  create    Image/freebsd-15
  create    Network/db
  create    Network/web
  create    Storage/fast
  create    Project/db
  create    Project/web
  create    FirewallPolicy/db/base
  create    FirewallPolicy/web/base
  create    BackupTarget/vault
  create    Jail/web/wiki

projects
  db
    web1         will be created
    web2         will be created
  web
    web1         will be created
    web2         will be created

22 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged
```
