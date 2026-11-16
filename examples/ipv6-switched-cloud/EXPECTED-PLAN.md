# The first plan

What `jailops-sync plan` prints for this fleet against a host that has nothing yet. The test suite compares it with
the real output on every run, so this page cannot go stale (regenerate with `JAILOPS_SYNC_REGEN_EXAMPLE=1 go test ./internal/fleet/e2e`).

```
host cloud1
  create    Image/freebsd-15
  create    Network/intra
  create    Network/shop
  create    Project/intra
  create    Project/shop
  create    AddressSet/intra/admins
  create    AddressSet/shop/admins
  create    AddressSet/shop/web-tier
  create    FirewallPolicy/intra/floor
  create    FirewallPolicy/intra/lan-only
  create    FirewallPolicy/shop/app-private
  create    FirewallPolicy/shop/floor
  create    FirewallPolicy/shop/public-web
  create    Jail/intra/wiki
  create    Jail/shop/app
  create    Jail/shop/web

projects
  intra
    cloud1       will be created
  shop
    cloud1       will be created

16 create, 0 update, 0 delete, 0 unchanged, 0 unmanaged
```
