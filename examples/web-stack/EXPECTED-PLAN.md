# The first plan

What `jailops-sync plan` prints for this fleet against a host that has nothing yet. The test suite compares it with
the real output on every run, so this page cannot go stale (regenerate with `JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e`).

```
host app1
  create    Image/freebsd-15
  create    Network/shop
  create    Project/shop
  create    AddressSet/shop/admins
  create    AddressSet/shop/app-tier
  create    FirewallPolicy/shop/app
  create    FirewallPolicy/shop/floor
  create    FirewallPolicy/shop/nginx
  create    FirewallPolicy/shop/postgres
  create    BackupTarget/vault
  create    BackupPolicy/shop/nightly
  create    Volume/shop/postgres-data
  create    Jail/shop/app
  create    Jail/shop/nginx
  create    Jail/shop/postgres

projects
  shop
    app1         will be created

15 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged
```
