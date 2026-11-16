# The first plan

What `jailops-sync plan` prints for this fleet against a host that has nothing yet. The test suite compares it with
the real output on every run, so this page cannot go stale (regenerate with `JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e`).

```
host db1
  create    Image/freebsd-15
  create    Network/shop
  create    Project/shop
  create    FirewallPolicy/shop/floor
  create    App/shop/db
              install app postgresql as jail db
  create    App/shop/web
              install app nginx as jail web
  create    AppAccess/shop/db from jail:web
              allow jail:web, database shop
  create    AppAccess/shop/web from 203.0.113.0/24
              allow 203.0.113.0/24 on 80/tcp

projects
  shop
    db1          will be created

8 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged
```
