# Examples

Every directory with a `fleet.yaml` below is a complete **jailops-sync** repository. They are not snippets: the test suite
runs `validate`, `render`, `plan`, `sync --apply` and a second `plan` on every one of them against in-memory hosts
(`internal/fleet/e2e`, `TestExamplesNeverRot`), checks each object with the daemon's own validators
(`internal/validate`, `TestExampleFleetsPassTheDaemonValidators`), and compares the first plan with the `EXPECTED-PLAN.md`
beside it. An example that stops working fails the build.

| Example | What it shows | Hosts |
|---|---|---|
| [`minimal-fleet`](minimal-fleet) | the smallest complete fleet: profiles, SOPS and age secrets, a rollout, mTLS to one host | 2 |
| [`ipv6-switched-cloud`](ipv6-switched-cloud) | a cloud server with a **shared /64** (NDP proxy mode): one `/80` per project, two segmented projects, a firewall per jail, a public web jail | 1 |
| [`ipv6-routed-hetzner`](ipv6-routed-hetzner) | a **routed /64**: one `/80` per project, no proxy involved | 1 |
| [`web-stack`](web-stack) | nginx, an app and PostgreSQL, a backup schedule and encrypted backups to a keyless backup node | 1 |
| [`big-pool-tank`](big-pool-tank) | a 16 TB HDD pool used as a storage, volumes, and an existing archive attached read-only as host-directory volumes | 1 |
| [`multi-host-fleet`](multi-host-fleet) | two hosts, one project across both, age and SOPS secrets, groups, a rollout | 2 |
| [`provisioning`](provisioning) | a fresh FreeBSD VM to a running fleet: install, `jailops-priv init`, services, `jailops-sync` from git | 1 |
| [`app-access-fleet`](app-access-fleet) | PostgreSQL and nginx from the application catalog (`App`), and who may reach them (`AppAccess`): a database role for the web jail, port 80 for a network | 1 |
| [`pkgops-packaged-service`](pkgops-packaged-service) | a Go service packaged with PkgOps installed into a jail by a provisioning step (what works, what is planned) | 1 |

Try any of them offline:

    jailops-sync -C examples/web-stack validate        # `check` is the same command
    jailops-sync -C examples/web-stack render          # what would be sent, secrets never decrypted

`validate`, `render` and `drift`-free planning need no host. `plan` and `sync --apply` talk to the hosts a fleet names, so
point `hosts/<host>/host.yaml` at your own first. The identity `example-identity.txt` opens the secrets of the examples and
**protects nothing real**: replace it (and the recipients in `.sops.yaml` and `secrets/recipients.txt`) before you use an
example for real.

Things every example follows, because the platform does:

- There is **no default project**. Every jail lives in a project, and names its network and its storage.
- A **network belongs to exactly one project**; storage may be shared between projects.
- Projects are closed to each other by default; a mandatory project policy (`firewall:` of the project) is a floor that no
  jail's own policy can lower.
- Webs are optional: the daemon and `jailops-sync` need no web console. See [../docs/exposure.md](../docs/exposure.md).
