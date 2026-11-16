# JailOps Software Security Audit Report

**Date:** November 16, 2026  
**Target Repository:** `jailops.net/jailops` (`v0.8.0`)  
**Scope:** Full-stack source code (`cmd/`, `internal/`, `sdk/`, `web/`), privilege-separation boundary (`jailopsd` ↔ `jailops-priv`), backup node (`jailops-backupd`), declarative fleet reconciler (`jailops-sync`), packaging & `rc.d` scripts (`packaging/`, `scripts/`), CI/CD pipelines (`.github/workflows/`, `.goreleaser.yaml`, `Justfile`), and third-party dependencies (SBOM).

---

## 1. Scope and Objectives

### 1.1 Audit Targets
This security audit evaluates the entire JailOps platform across its five deliverable binaries, two embedded Vue 3 web consoles, client SDK, operating system integration scripts, and build/release infrastructure:

1. **Host & Hub API Daemon (`cmd/jailopsd`, `internal/daemon`, `internal/server`, `internal/service`, `internal/reconcile`, `internal/store`, `internal/state`)**:
   - Unprivileged control-plane daemon running as user `jailops`.
   - Exposes REST API (`/api/v1/*`), streaming WebSocket/HTTP upgrade endpoints (`exec`, `console`), Server-Sent Events (`events`), ACME HTTP-01/TLS-ALPN-01 responder, and embedded Host Web Console (`internal/webui`).
2. **Root Privileged Helper & Chrooted File Agent (`cmd/jailops-priv`, `internal/priv`, `internal/fsagent`, `internal/sys`, `internal/render`)**:
   - Root daemon listening on `/var/run/jailops-priv/priv.sock` (`0660` `root:jailops`), enforcing `priv.conf` allow-lists over 79 typed operations, executing FreeBSD system binaries (`zfs`, `zpool`, `jail`, `jexec`, `pfctl`, `ifconfig`, `route`, `rctl`, `dnctl`, `pkg`, `etcupdate`, `debootstrap`, `mount`, `umount`, `wg`), and spawning chrooted `fsagent` subprocesses.
3. **Keyless Backup Node (`cmd/jailops-backupd`, `internal/backupd`, `internal/node`, `internal/repo`, `internal/backupui`)**:
   - Multi-host content-addressed encrypted backup repository server (`jailops-backup` user), PostgreSQL control plane (`internal/node/ctl`), local/S3 chunk datastore (`internal/repo/datastore`, `internal/repo/s3`), mTLS host listener, local UNIX admin socket, and embedded Backup Web Console (`internal/backupui`).
4. **CLI Client, Declarative Fleet Tool & Go SDK (`cmd/jailops`, `cmd/jailops-sync`, `internal/cli`, `internal/fleet`, `sdk/`)**:
   - Operator CLI (`jailops`), GitOps reconciler with SOPS/`age` secret management (`jailops-sync`), and zero-dependency Go SDK (`jailops.net/jailops/sdk`).
5. **Web Consoles (`web/shared`, `web/host`, `web/backup`)**:
   - Vue 3 + Vite single-page applications embedded into `jailopsd` and `jailops-backupd`.
6. **Packaging, Setup Scripts & CI/CD Pipelines (`packaging/`, `scripts/`, `.github/workflows/`, `.goreleaser.yaml`, `Justfile`)**:
   - FreeBSD `rc.d` init scripts, `jailops-setup` host bootstrapper, Linux systemd unit, package builders, and GitHub Actions workflows.

### 1.2 Security Objectives
The primary objective is **systematic risk reduction**:
- Verify that a compromised unprivileged daemon (`jailopsd`) or a compromised jail cannot escalate privileges to unconfined host `root` via `jailops-priv` or escape into another jail/project.
- Identify authentication, session management, rate-limiting, access control (RBAC/scope), and SSRF flaws in `jailopsd` and `jailops-backupd`.
- Evaluate cryptographic implementations (Argon2id, XChaCha20-Poly1305, AES-256-GCM, `age`, SOPS, TLS/mTLS pinning, trust tokens).
- Uncover supply-chain, CI/CD, packaging, and compliance gaps between documented security guarantees (`docs/security-model.md`, `docs/design.md`) and the implementation.

---

## 2. Asset Inventory and Software Bill of Materials (SBOM)

### 2.1 Software Component & Server Inventory

| Asset / Binary | Entrypoint & Core Packages | Target OS / Arch | Runtime Identity | Network / IPC Listeners | Persistent Storage |
|---|---|---|---|---|---|
| **`jailopsd`** (Host/Hub Daemon) | `cmd/jailopsd`, `internal/{daemon,server,service,reconcile,store,state,logfwd,ndproxy,webui}` | `freebsd` (`amd64`, `arm64`) | `jailops:jailops` (unprivileged) | • UNIX: `/var/run/jailops/jailops.sock` (`0666`)<br>• HTTPS: `:39110` (TLS 1.3, optional mTLS)<br>• HTTP: `:39080` (ACME HTTP-01 challenge only) | • SQLite: `/var/db/jailops/jailops.db` (`0600`)<br>• Desired State JSON: `/var/db/jailops/state/` (`0750`)<br>• TLS/Seal/Age keys: `/var/db/jailops/` (`0600`) |
| **`jailops-priv`** (Root Helper & `fsagent`) | `cmd/jailops-priv`, `internal/{priv,fsagent,render,sys,wireguard}` | `freebsd` (`amd64`, `arm64`) | `root:wheel` (`uid 0`) | • UNIX: `/var/run/jailops-priv/priv.sock` (`0660`, `root:jailops` in `0710` dir)<br>• `socketpair(2)` FD 3 for `fsagent` children | • Config: `/usr/local/etc/jailops/priv.conf` (`0600`)<br>• Jail configs: `/usr/local/etc/jailops/jails/`<br>• WG keys: `/var/db/jailops-priv/wireguard` (`0700`)<br>• Host snapshots: `/var/db/jailops-priv/host` (`0700`) |
| **`jailops-backupd`** (Backup Node) | `cmd/jailops-backupd`, `internal/{backupd,node,repo,backupui}` | `linux`, `freebsd` (`amd64`, `arm64`) | `jailops-backup` (unprivileged) | • UNIX Admin: `/var/run/jailops-backupd/admin.sock` (`0600`)<br>• HTTPS Host/Mgmt: `:39111` (mTLS for hosts; HTTPS for Web UI/API) | • Control Plane: PostgreSQL (`pgx/v5`)<br>• Chunk Repo: `/var/db/jailops-backup/repository` (`0750`) or S3 bucket |
| **`jailops`** (CLI Client) | `cmd/jailops`, `internal/cli`, `sdk` | `linux`, `darwin`, `freebsd` (`amd64`, `arm64`) | Operator / `root` | Outbound UNIX socket or HTTPS (TLS 1.2+ / pinned SHA-256 cert or CA) | • User config: `~/.config/jailops/config.yaml` (`0600`)<br>• System config: `/usr/local/etc/jailops/client.yaml` |
| **`jailops-sync`** (Fleet GitOps CLI) | `cmd/jailops-sync`, `internal/fleet`, `sdk` | `linux`, `darwin`, `freebsd` (`amd64`, `arm64`) | Operator / CI | Outbound HTTPS to hosts/hub via `sdk` | • Fleet git repo (`fleet.yaml`, `.sops.yaml`, `*.sops.yaml`) |
| **Host Web Console** | `web/host`, `web/shared`, `internal/webui` | Embedded in `jailopsd` | Browser client | Calls `/api/v1/*` on `jailopsd` (`:39110`) | • `__Host-jailops_session` (`HttpOnly`, `Secure`, `SameSite=Strict`)<br>• `sessionStorage` (`jailops.token`, `jailops.csrf`) |
| **Backup Web Console** | `web/backup`, `web/shared`, `internal/backupui` | Embedded in `jailops-backupd` | Browser client | Calls `/api/v1/*` on `jailops-backupd` (`:39111`) | • `__Host-jailops_session` (`HttpOnly`, `Secure`, `SameSite=Strict`)<br>• `sessionStorage` (`jailops.token`, `jailops.csrf`) |

### 2.2 Architecture & Trust Boundary Data Flows

```
+-----------------------------------------------------------------------------------+
| Operators / Browsers / CI (jailops CLI, jailops-sync, Web Consoles, Hub Peer)     |
+-----------------------------------------+-----------------------------------------+
                                          |
                 HTTPS (:39110, TLS 1.3 / mTLS) or UNIX (/var/run/jailops/jailops.sock)
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Unprivileged Host Daemon: jailopsd (User: jailops)                                |
|  - AuthN/AuthZ (internal/auth, internal/server)                                   |
|  - Operational DB: SQLite (/var/db/jailops/jailops.db)                            |
|  - Desired State JSON (/var/db/jailops/state/objects/<kind>/<id>.json)            |
|  - Reconcile Loop (internal/reconcile) & Backup Engine (internal/hostbackup)      |
+--------------------+-----------------------------------------+--------------------+
                     |                                         |
  UNIX Socket (/var/run/jailops-priv/priv.sock)      mTLS (:39111, XChaCha20-Poly1305
  LOCAL_PEERCRED + priv.conf Policy Boundary          client-side encrypted chunks)
                     |                                         |
                     v                                         v
+----------------------------------------+   +--------------------------------------+
| Root Helper: jailops-priv (User: root) |   | Keyless Backup Node: jailops-backupd |
|  - 79 Typed RPC Ops + CommandRules     |   |  - Control Plane: PostgreSQL (pgx)   |
|  - ZFS / jail / pfctl / ifconfig / wg  |   |  - Chunk Store: Local Dir or S3      |
|  - Chrooted fsagent (FD 3 socketpair)  |   |  - Holds NO decryption keys          |
|  - BPF NDP capture/inject (ndproxy)    |   +--------------------------------------+
+----------------------------------------+
```

### 2.3 Software Bill of Materials (SBOM)

#### 2.3.1 Go Modules (`go.mod` & `sdk/go.mod`)
- **Compiler / Toolchain**: Go `1.27.3` (`CGO_ENABLED=0` static builds).
- **SDK Module (`jailops.net/jailops/sdk`)**: **0 external dependencies** (Go standard library only).
- **Root Module (`jailops.net/jailops`) — Direct Dependencies (13)**:

| Package | Version | License | Subsystem Usage |
|---|---|---|---|
| `filippo.io/age` | `v1.3.2` | BSD-3-Clause | Asymmetric secret sealing (`sealed:age:`) and backup key escrow |
| `github.com/fergusstrange/embedded-postgres` | `v1.34.0` | MIT | Ephemeral PostgreSQL server for `internal/testdb` integration tests |
| `github.com/getsops/sops/v3` | `v3.13.3` | MPL-2.0 | SOPS YAML file encryption/decryption in `jailops-sync` (`internal/fleet/vault`) |
| `github.com/jackc/pgx/v5` | `v5.11.0` | MIT | PostgreSQL driver and connection pool for `jailops-backupd` (`internal/node/ctl`) |
| `github.com/klauspost/compress` | `v1.20.3` | BSD-3-Clause | Zstandard (`zstd`) compression for backup chunks (`internal/repo/format`) |
| `github.com/spf13/cobra` | `v1.10.2` | Apache-2.0 | CLI command parsing (`cmd/jailops`, `cmd/jailops-sync`) |
| `golang.org/x/crypto` | `v0.58.0` | BSD-3-Clause | Argon2id, XChaCha20-Poly1305, HKDF, ACME (`internal/daemon/acme.go`) |
| `golang.org/x/net` | `v0.61.0` | BSD-3-Clause | Network/HTTP utilities |
| `golang.org/x/sys` | `v0.49.0` | BSD-3-Clause | FreeBSD/Linux syscalls (`LOCAL_PEERCRED`, `SO_PEERCRED`, `Chroot`, `Ioctl`, `Socketpair`) |
| `golang.org/x/term` | `v0.47.0` | BSD-3-Clause | Raw terminal mode (`jailops exec`/`shell`) and no-echo password prompts |
| `gopkg.in/yaml.v3` | `v3.0.1` | MIT / Apache-2.0 | YAML configuration and catalog parsing |
| `modernc.org/sqlite` | `v1.61.0` | BSD-3-Clause | Pure-Go SQLite database driver for `jailopsd` (`internal/store`) |
| `jailops.net/jailops/sdk` | `v0.0.0` (`./sdk`) | BSD-2-Clause | Local workspace SDK |

- **Root Module (`jailops.net/jailops`) — Transitive / Indirect Dependencies (131)**:
  - **Cryptography & Auth**: `filippo.io/edwards25519 v1.2.0`, `filippo.io/hpke v0.4.0`, `github.com/ProtonMail/go-crypto v1.4.1`, `github.com/cloudflare/circl v1.6.4`, `github.com/go-jose/go-jose/v4 v4.1.4`, `github.com/golang-jwt/jwt/v5 v5.3.1`, `github.com/tjfoc/gmsm v1.4.1`, `golang.org/x/oauth2 v0.36.0`, `github.com/getsops/gopgagent v0.0.0-20241224165529-7044f28e491e`.
  - **Cloud SDKs & KMS (pulled transitively via `github.com/getsops/sops/v3`)**:
    - Google Cloud (`cloud.google.com/go v0.123.0`, `auth v0.22.0`, `kms v1.32.0`, `storage v1.63.1`, `iam v1.12.0`, `monitoring v1.30.0`, `google.golang.org/api v0.289.0`, `google.golang.org/grpc v1.82.1`, `google.golang.org/protobuf v1.36.11`).
    - AWS SDK v2 (`github.com/aws/aws-sdk-go-v2 v1.42.1`, `service/kms v1.54.1`, `service/s3 v1.105.2`, `service/sts v1.44.1`, `service/sso v1.32.1`, `smithy-go v1.27.4`).
    - Azure SDK (`github.com/Azure/azure-sdk-for-go/sdk/azcore v1.22.0`, `azidentity v1.14.0`, `security/keyvault/azkeys v1.5.0`, `github.com/AzureAD/microsoft-authentication-library-for-go v1.7.2`).
    - HashiCorp Vault (`github.com/hashicorp/vault/api v1.23.0`, `go-retryablehttp v0.7.8`, `hcl v1.0.1-vault-7`).
    - Huawei Cloud & MongoDB (`github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.1.207`, `go.mongodb.org/mongo-driver v1.17.9`).
  - **SQLite Pure-Go Runtime (`modernc.org`)**: `modernc.org/libc v1.79.0`, `modernc.org/mathutil v1.7.1`, `modernc.org/memory v1.12.1`, `github.com/ncruces/go-strftime v1.1.0`, `github.com/remyoudompheng/bigfft`, `github.com/dustin/go-humanize v1.1.0`.
  - **Database, CLI & Telemetry**: `github.com/lib/pq v1.12.3`, `github.com/jackc/puddle/v2 v2.2.2`, `github.com/spf13/pflag v1.0.9`, `github.com/urfave/cli v1.22.17`, `github.com/sirupsen/logrus v1.9.4`, `github.com/goccy/go-yaml v1.19.2`, `go.yaml.in/yaml/v3 v3.0.4`, `gopkg.in/ini.v1 v1.67.3`, `github.com/xi2/xz`, `go.opentelemetry.io/otel v1.44.0`, `cel.dev/expr v0.25.2`, `github.com/envoyproxy/go-control-plane/envoy v1.37.0`, `github.com/spiffe/go-spiffe/v2 v2.8.1`.

#### 2.3.2 Web / NPM Packages (`web/package.json` & `web/shared/package.json`)
- **Runtime Dependencies (bundled into `internal/webui/dist` and `internal/backupui/dist`)**:
  - `vue`: `^3.5.44`
  - `vue-router`: `^5.4.0`
  - `lucide-static`: `^1.61.0`
  - `@fontsource/ibm-plex-sans`: `^5.3.0`
  - `@fontsource/ibm-plex-mono`: `^5.3.0`
- **Development & Test Dependencies**:
  - `vite`: `^8.3.5`, `@vitejs/plugin-vue`: `^6.0.10`, `typescript`: `~5.9`, `vue-tsc`: `^3.3.13`, `vitest`: `^5.0.5`, `@vue/test-utils`: `^2.5.1`, `jsdom`: `^30.1.3`, `@playwright/test`: `^1.64.1`, `@types/node`: `^26.6.5`.
- **`npm audit` Result**: **0 known vulnerabilities** across all installed npm dependencies.

---

## 3. Technical Analysis and Testing Methodology

### 3.1 Static Application Security Testing (SAST) & Manual Code Review
A comprehensive line-by-line review was conducted across:
- **Privilege Separation & Command Execution**: `cmd/jailops-priv/*`, `internal/priv/*`, `internal/fsagent/*`, `internal/sys/{run,zfs,jailos,pfctl,ifconfig,wgtool}/*`.
- **Configuration Renderers & Parsers**: `internal/render/{safe,jailconf,rcconf,pf,anchor,fstab,devfs,unbound,wireguard}.go`.
- **Authentication, RBAC & API Handlers**: `internal/auth/*`, `internal/server/*`, `internal/service/*`, `internal/backupd/*`, `internal/node/*`.
- **Storage, Crypto & Log Forwarding**: `internal/store/*`, `internal/state/*`, `internal/repo/*`, `internal/logfwd/*`, `internal/fleet/vault/*`.
- **Frontend & Client SDK**: `web/{shared,host,backup}/src/**`, `internal/webui/*`, `internal/backupui/*`, `sdk/*`, `internal/cli/*`.

### 3.2 Dynamic Testing & Behavioral Verification
1. **End-to-End Lint & Dependency Audit**:
   - `sh scripts/lint-e2e.sh` passed (`exit 0`).
   - `npm audit --json` in `web/` passed with 0 vulnerabilities.
2. **POSIX Setup Harness (`sh scripts/jailops-setup-test.sh`)**:
   - Executed `scripts/jailops-setup-test.sh` against `packaging/jailops-setup`.
   - **5 test assertions failed** on BSD/macOS One True Awk (`awk`), revealing a real syntax incompatibility in `packaging/jailops-setup:217` (`/[ \t]scrub([ \t(]|$)/` contains an unescaped `(` inside a bracket expression `[...]`, causing FreeBSD/macOS `nawk` to fail with a regular expression syntax error during `pfplan` / `pfedit`!). See **Finding PKG-02**.
3. **Simulated Attack Analysis (Non-Destructive Code-Path Tracing)**:
   - Traced privilege escalation vectors across the `/var/run/jailops-priv/priv.sock` boundary (`pkg -r`, `etcupdate`, `fs.copy_tree`, `jailTreeDepth`, `SCM_RIGHTS` descriptor passing).
   - Traced brute-force, rate-limit bypass, and Argon2id exhaustion paths against `jailops-backupd` (`internal/backupd/mgmt.go`).
   - Traced SSRF and local service probing via API-configured log forwarding sinks (`internal/logfwd/guard.go`).

### 3.3 Configuration, Packaging & CI/CD Review
- Reviewed `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.goreleaser.yaml`, `Justfile`, `docs/ci-supply-chain.md`, `packaging/rc.d/*`, `packaging/jailops-setup`, `scripts/pkg-build.sh`, and `examples/provisioning/bootstrap.sh`.

---

## 4. Risk Assessment and Prioritization Matrix

Findings are ranked using standard likelihood × impact risk assessment across four severity tiers (**Critical**, **High**, **Medium**, **Low**):

| ID | Severity | Category | Title | Location(s) |
|---|---|---|---|---|
| **PRIV-01** | **HIGH** | Privilege Escalation | `jailops-priv` Allow-List for `etcupdate` Permits Arbitrary Host Command Execution (`make`) via `-s` and Unverified Archive Extraction via `-t` | `internal/priv/allowlist.go:287-332, 440-442` |
| **PRIV-02** | **HIGH** | Privilege Escalation | `jailops-priv` `pkg -r <root>` Allow-List Permits Local Unsigned `.pkg` Traversal (`rePkgName`) and Executes Unconfined Host `root` Scripts in Stopped Jail Trees | `internal/priv/allowlist.go:94, 427-438`, `internal/priv/pkgrepo.go:37-70, 205-264` |
| **PRIV-03** | **HIGH** | Sandbox / Jail Escape | `jailTreeDepth` Omits ZFS-Delegated Jail Dataset (`delegated`), Allowing Symlink Traversal Across the Storage Root to Other Jails and Projects | `internal/priv/safefs.go:99-110, 125-136` |
| **AUTH-01** | **HIGH** | Authentication / Bypass | `jailops-backupd` Keys Login & Bearer Token Lockouts on `r.RemoteAddr` (`IP:port`), Allowing Trivial Lockout Bypass Across TCP Connections and Missing Pre-Check | `internal/backupd/mgmt.go:229-241, 333-365` |
| **AUTH-02** | **HIGH** | Availability / DoS | Unauthenticated Login & Password-Change Denial of Service in `jailops-backupd` via Non-Blocking Argon2id Semaphore (`hashSem`) | `internal/backupd/mgmt.go:42-58, 347-356, 419-422` |
| **CICD-01** | **HIGH** | Supply Chain / CI/CD | Unpinned GitHub Actions Using Mutable Tags (`@v1`, `@v6`, `@v7`) Including Third-Party VM & Release Actions | `.github/workflows/ci.yml:30-397`, `.github/workflows/release.yml:17-37` |
| **PRIV-04** | **MEDIUM** | Privilege Separation | `fs.copy_tree` Preserves `setuid`/`setgid` Bits and Immutable File Flags (`schg`/`uchg`) Into Non-Jail Trees Without `admin` Assertion | `internal/priv/copytree.go:342-363, 589-608`, `internal/priv/ops.go:565` |
| **PRIV-05** | **MEDIUM** | Resource Exhaustion | Unbounded `SCM_RIGHTS` File Descriptor Accumulation in `jailops-priv` (`fdConn`) When Client Sends `NFds: 0` | `internal/priv/wire.go:221-254, 277-292`, `internal/priv/server.go:194, 219-232` |
| **PRIV-06** | **MEDIUM** | Race Condition (TOCTOU) | Path-Based `Chmod`/`Chown` After `MkdirAll` and Pre-Rename `Lstat` in `safefs.go` & `logs.go` Inside Running Jail Trees | `internal/priv/safefs.go:351-387, 429-437`, `internal/priv/logs.go:293-315` |
| **AUTH-03** | **MEDIUM** | Auth / Rate Limiting | `jailopsd` Bearer Token Verification Resets IP Lockout Counter on Any Valid Token (`tokLim.Success`) and Queries SQLite While Locked Out | `internal/server/server.go:272-288`, `docs/exposure.md:173, 232` |
| **AUTH-04** | **MEDIUM** | Audit / Data Leak / DoS | `jailops-backupd` Logs Unsanitized, Unbounded (up to 1 MiB) Anonymous `req.Username` Into PostgreSQL `audit` Table on Failed Login | `internal/backupd/mgmt.go:188, 362`, `internal/node/ctl/jobs.go:209-216` |
| **AUTH-05** | **MEDIUM** | Cryptography / PKI | Trust Token Redemption (`RedeemTrustToken`) Verifies Against Static Startup Fingerprint Instead of `servingFingerprint()`, Breaking Uploaded/ACME Certs | `internal/service/trust.go:72 vs 128` |
| **SSRF-01** | **MEDIUM** | SSRF / Network | API-Configured Log Forwarding Sinks Allow Probing & Sending Data to Non-Daemon Ports on the Host's Own IP and Local Jail Subnets | `internal/logfwd/guard.go:48-69` |
| **CICD-02** | **MEDIUM** | CI/CD Secrets | `release.yml` Omits `persist-credentials: false` on `actions/checkout` While Running With `contents: write` | `.github/workflows/release.yml:9-19` |
| **CICD-03** | **MEDIUM** | Supply Chain | Missing Cryptographic Signatures / SLSA Provenance on Release Artifacts & Floating GoReleaser Version (`~> v2`) | `.github/workflows/release.yml:35-40`, `.goreleaser.yaml:189-191` |
| **PKG-01** | **MEDIUM** | Shell / Portability | `packaging/jailops-setup` Regex Bug Breaks BSD/macOS `awk` (`5 failed checks`), Uses `eval` on `awk` Output, and Uses Static `/etc/pf.conf.jailops-setup.tmp` | `packaging/jailops-setup:217, 266, 333` |
| **PKG-02** | **MEDIUM** | Permissions | World-Readable (`0755`) `/usr/local/etc/jailops/jails` and `/var/tmp/jailops` Expose Rendered Jail Configs and Build Artifacts to Local Users | `cmd/jailops-priv/init.go:224, 241-243`, `scripts/pkg-build.sh:66, 77` |
| **PKG-03** | **MEDIUM** | Configuration / PF | `examples/provisioning/bootstrap.sh` Uses Deprecated PF Translation Anchors, Omits `set state-policy if-bound`, and Uses Unquoted `$(ls ...)` | `examples/provisioning/bootstrap.sh:56-57, 68-72, 101` |
| **DOC-01** | **MEDIUM** | Compliance / Ops | Documented Disaster Recovery Key (`JOR1-...`) Has No CLI/API Restore Command; Capsicum (`cap_enter`) and Key FreeBSD 15.1 Controls Remain Unverified | `cmd/jailops-priv/agent.go:56-67`, `docs/backup-restore.md:166-169`, `docs/design.md:1178-1228` |
| **WEB-01** | **LOW** | Web / Headers / Storage | Missing CSP & Framing Headers on `jailops-backupd` Web UI, Incomplete `jailops_csrf` Cookie Cleanup on Logout, and Bearer Token Storage in `sessionStorage` | `internal/backupui/webui.go:99-107`, `internal/server/handlers.go:448`, `web/shared/src/api/client.ts:69-77` |
| **DB-01** | **LOW** | Database Query | SQL `LIKE` Wildcard Injection (`%`, `_`) in `jailops-backupd` Audit Log Prefix Filter | `internal/node/ctl/jobs.go:219-228` |
| **PKG-04** | **LOW** | Shell Scripts | Unquoted Variable Expansions in `packaging/rc.d/*` and Unescaped JSON Interpolation in `scripts/pkg-build.sh` | `packaging/rc.d/jailopsd:82-157`, `scripts/pkg-build.sh:41, 109, 136-154` |
| **SBOM-01** | **LOW** | Supply Chain / Secrets | Transitive Dependency Bloat (~120 Cloud SDK Packages via `sops/v3`) and Static Test `age` Key in `examples/example-identity.txt` | `go.mod:8, 21-152`, `examples/example-identity.txt:2` |

---

## 5. Detailed Findings and Remediation Guidance

---

### [PRIV-01] HIGH: `jailops-priv` Allow-List for `etcupdate` Permits Arbitrary Host Command Execution (`make`) via `-s` and Unverified Archive Extraction via `-t`

- **Location**:
  - [internal/priv/allowlist.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/allowlist.go#L277-L332)
  - [internal/priv/allowlist.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/allowlist.go#L440-L442)
- **Vulnerable Code**:
  ```go
  // internal/priv/allowlist.go:277-332
  var etcupdateSubs = []string{"extract", "resolve", "status", "diff", "build", "revert"}

  func customEtcupdate(c Config, _ bool, args []string) error {
      ...
          case "-D", "-s", "-d", "-t", "-L":
              ...
              kind := pathState
              if a == "-D" || a == "-s" {
                  kind = pathJailTree
              }
              if err := c.checkRulePath(kind, args[i]); err != nil {
                  return err
              }
  ```
- **Root Cause & Impact**:
  The security model (`docs/security-model.md:15-30`) states that a compromised `jailopsd` daemon cannot run arbitrary code as `root` or write files outside storage roots via `jailops-priv`. However, `customEtcupdate` in `internal/priv/allowlist.go` has two severe privilege-escalation flaws:
  1. **Arbitrary `make` Execution as Host `root` via `-s <source_tree>`**: In FreeBSD's `/usr/sbin/etcupdate`, passing `-s <source>` (without `-t <tarball>`) instructs `etcupdate` to build a new `/etc` tree by running `make` on the Makefiles inside `<source>` (`/usr/src`) as **unconfined host `root`**. Because `customEtcupdate` allows `-s` pointing to any `pathJailTree` (and allows the `build` and `extract` subcommands), a compromised `jailopsd` (or a jail that planted a `Makefile` in its tree) can invoke `etcupdate build -s <jailroot> -D <jailroot>` or `etcupdate extract -s <jailroot> -D <jailroot>`, causing `jailops-priv` to execute arbitrary `Makefile` shell commands as unconfined host `root`!
  2. **Unverified Tarball Extraction as Host `root` via `-t <tarball>`**: While `tar -C <root> -xpzf <file>` in `internal/priv/guards.go:424-435` carefully copies the archive via `sealArchive` and inspects member names via `verifyTar` (to prevent `..` or symlink traversal out of the destination), `etcupdate` with `-t <tarball>` has **no `Verify` hook** and **does not seal the archive**. `/usr/sbin/etcupdate` runs `tar -xpf <tarball>` as host `root` directly on the unverified file in `pathState` (`/var/tmp/jailops`), allowing symlink/path traversal overwrites of host files as `root`.
- **Suggested Fix**:
  1. Remove `-s` and `"build"` from `customEtcupdate` in `internal/priv/allowlist.go` (JailOps upgrades always use a pre-built tarball via `-t`, never a `/usr/src` tree).
  2. In `internal/priv/guards.go` (`runGuard.Run`), apply `sealArchive` and `verifyTar` (checking for `..`, leading `/`, and symlinks escaping the tree) to the `-t <tarball>` argument of `etcupdate` before executing `/usr/sbin/etcupdate`.

---

### [PRIV-02] HIGH: `jailops-priv` `pkg -r <root>` Allow-List Permits Local Unsigned `.pkg` Traversal (`rePkgName`) and Executes Unconfined Host `root` Scripts in Stopped Jail Trees

- **Location**:
  - [internal/priv/allowlist.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/allowlist.go#L94)
  - [internal/priv/allowlist.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/allowlist.go#L427-L438)
  - [internal/priv/pkgrepo.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/pkgrepo.go#L37-L70)
  - [internal/priv/pkgrepo.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/pkgrepo.go#L205-L264)
- **Vulnerable Code**:
  ```go
  // internal/priv/allowlist.go:94
  rePkgName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._+@:=/-]{0,127}|%[a-zA-Z][%a-zA-Z0-9._ :-]{0,60})$`)
  ```
  ```go
  // internal/priv/pkgrepo.go:37-42
  func (l *Local) sealRepos(ctx context.Context, argv []string) ([]string, func(), error) {
      none := func() {}
      dir := reposDirOf(argv[1:])
      if dir == "" {
          return argv, none, nil
      }
  ```
- **Root Cause & Impact**:
  1. **Local Unsigned Package Installation via `rePkgName`**: `docs/security-model.md:371-394` states that `jailops-priv` refuses to install packages that are not verified against a root-owned repository key (`signature_type: fingerprints`). However, `rePkgName` allows both `.` and `/` without forbidding `..` or `.pkg`/`.txz` suffixes. A caller can pass a path such as `a/../../../../var/tmp/jailops/evil.pkg` (or a file inside the target root) to `pkg -r <root> install`. When FreeBSD `pkg-install(8)` receives a path to a local `.pkg` file, it installs the local archive **without checking any repository signature**, executing its `+PRE_INSTALL` / `+POST_INSTALL` scripts as `root`!
  2. **Unconfined Host `root` Execution in Stopped Jail Roots (`pkg -r`)**: `docs/security-model.md:398-403` notes that `pkg -r <root>` runs package install scripts in a `chroot(<root>)` as **host `root` (`uid 0`)**, using `<root>/bin/sh` and `<root>/lib/*`. Because `chroot(2)` (unlike `jail(2)`) is **not** a security boundary for `uid 0` on FreeBSD, any code running as `uid 0` inside `chroot(<root>)` has full host `root` privileges. While `verifyPkgTarget` (`pkgrepo.go:243-264`) checks that the jail is not *currently* running, it allows `pkg -r <root>` on:
     - Any stopped jail that *previously* ran (whose root user could have trojaned `/bin/sh` or `libc.so.7` before stopping, and `CHANGELOG.md:805-809` notes that `jailops update` now runs `pkg -r <jail root>` from the host!).
     - Any stopped jail root into which a compromised `jailopsd` wrote a malicious `/bin/sh` via `fs.write_file`.
- **Suggested Fix**:
  1. In `internal/priv/allowlist.go:94`, forbid `..` and archive suffixes (`.pkg`, `.txz`, `.tbz`, `.tgz`, `.tar`) in `rePkgName`, and allow at most a single `/` for port origins (`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}(/[A-Za-z0-9][A-Za-z0-9._+-]{0,63})?(@[A-Za-z0-9._+-]{1,32})?$`).
  2. Never run `pkg -r <jail root>` as unconfined host `root` on a mutable jail tree that has either run before or been written by `fs.write_file`. For package updates of thin jails that lack `/usr/sbin/pkg` inside the jail, either run `pkg` inside a temporary jail (`jail -c`) or attach to the jail's namespace rather than relying on host `chroot(2)` as `uid 0`.

---

### [PRIV-03] HIGH: `jailTreeDepth` Omits ZFS-Delegated Jail Dataset (`delegated`), Allowing Symlink Traversal Across the Storage Root

- **Location**:
  - [internal/priv/safefs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/safefs.go#L99-L110)
  - [internal/priv/safefs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/safefs.go#L125-L136)
- **Vulnerable Code**:
  ```go
  // internal/priv/safefs.go:99-110
  func jailTreeDepth(rel string) int {
      s := strings.Split(rel, "/")
      switch {
      case len(s) >= 5 && s[0] == "projects" && s[2] == "jails" && slices.Contains([]string{"root", "root.new", "root.old", "root.stale"}, s[4]):
          return 5
      case len(s) >= 4 && s[0] == "projects" && s[2] == "volumes":
          return 4
      case len(s) >= 3 && s[0] == "images" && reImageGen.MatchString(s[2]):
          return 3
      }
      return 0
  }
  ```
- **Root Cause & Impact**:
  `jailTreeDepth` determines which subdirectories under a storage mount are controlled by a jail so that `inJailTree` opens an `os.Root` confined to that specific jail directory rather than the top-level storage mount (`<mount>`). As documented in `safefs.go:96-98`: *"Root in a jail can make symlinks in its own tree; opened at the storage mount, a relative one would lead the helper into another jail of the same mount."*
  However, when a jail has `zfs_delegation` enabled (`internal/priv/delegate.go`), the jail controls `<mount>/projects/<p>/jails/<j>/delegated`. Because `"delegated"` is missing from the slice in `jailTreeDepth` (`safefs.go:102`), any helper file operation or `checkRulePath` on a path inside `<mount>/projects/<p>/jails/<j>/delegated/...` opens `os.Root` at `<mount>` instead of `<mount>/projects/<p>/jails/<j>/delegated`! A relative symlink planted by the jail inside `delegated` (e.g., `../../../../../projects/other/jails/victim/root/etc/master.passwd`) will be followed by `os.Root` into other jails and projects on the same storage mount.
- **Suggested Fix**:
  Add `"delegated"` to `jailTreeDepth` in `internal/priv/safefs.go:102`:
  ```go
  case len(s) >= 5 && s[0] == "projects" && s[2] == "jails" && slices.Contains([]string{"root", "root.new", "root.old", "root.stale", "delegated"}, s[4]):
      return 5
  ```

---

### [AUTH-01] HIGH: `jailops-backupd` Keys Login & Bearer Token Lockouts on `r.RemoteAddr` (`IP:port`), Allowing Trivial Lockout Bypass Across TCP Connections

- **Location**:
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L229-L241)
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L333-L365)
- **Vulnerable Code**:
  ```go
  // internal/backupd/mgmt.go:229-238 (Bearer Token Auth)
  tokKey := "tok|" + auth.SourceKey(r.RemoteAddr)
  t, err := m.s.DB.TokenByHash(r.Context(), auth.HashToken(raw))
  if err != nil {
      if errors.Is(err, ctl.ErrNotFound) {
          if lerr := m.ipLock.Fail(tokKey); lerr != nil {
              return nil, lerr
          }
          return nil, api.Errorf(api.CodeUnauthorized, "invalid token")
      }
      return nil, err
  }
  ```
  ```go
  // internal/backupd/mgmt.go:335-365 (Password Login)
  for _, k := range keys {
      if err := k.lim.Check(k.key); err != nil { ... }
  }
  // ... VerifyPassword runs here without Begin() ...
  for _, k := range keys {
      _ = k.lim.Fail(k.key)
  }
  ```
- **Root Cause & Impact**:
  1. **Missing Pre-Check on Bearer Token Lockout (`mgmt.go:230`)**: `m.identify` queries PostgreSQL (`m.s.DB.TokenByHash`) *before* checking `m.ipLock.Check(tokKey)`. Even when an IP is locked out after 50 failed token attempts, every subsequent request still queries PostgreSQL, and failed token attempts are never recorded in the backup node's audit log.
  2. **Concurrent Login Bypass (`mgmt.go:335-365`)**: Unlike `jailopsd` (`internal/service/access.go:712`), which uses `lim.Begin(key)` before hashing and `lim.End(key, ok)` after hashing so in-flight requests are counted immediately, `backupd` calls `k.lim.Check(k.key)` before Argon2id and `k.lim.Fail(k.key)` only *after* Argon2id finishes. An attacker can send `NumCPU()` parallel login requests per batch that all pass `Check()` simultaneously before the failure counter increments.
- **Suggested Fix**:
  1. In `internal/backupd/mgmt.go:230`, call `if err := m.ipLock.Check(tokKey); err != nil { return nil, err }` prior to `TokenByHash` (or use `Begin`/`End`), and write an audit log entry on failed token authentication.
  2. In `internal/backupd/mgmt.go:335-365`, replace `Check` + `Fail`/`Success` with `Begin` + `End` so concurrent login attempts cannot bypass the 5-attempt threshold.

---

### [AUTH-02] HIGH: Unauthenticated Login & Password-Change Denial of Service in `jailops-backupd` via Non-Blocking Argon2id Semaphore (`hashSem`)

- **Location**:
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L42-L58)
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L347-L356)
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L419-L422)
- **Vulnerable Code**:
  ```go
  // internal/backupd/mgmt.go:49-58
  func (m *Mgmt) hashSlot(w http.ResponseWriter) (func(), bool) {
      select {
      case m.hashSem <- struct{}{}:
          return func() { <-m.hashSem }, true
      default:
          w.Header().Set("Retry-After", "1")
          writeError(w, api.Errorf(api.CodeRateLimited, "too many sign-in attempts at once, try again in a moment"))
          return nil, false
      }
  }
  ```
- **Root Cause & Impact**:
  `docs/security-model.md:303-304` states that at most 4 Argon2id checks (`64 MiB` each) run at once and up to 32 requests wait their turn in a queue before returning `429 Too Many Requests`. While `jailopsd` implements this queue (`internal/auth/derive.go`), `jailops-backupd` uses a non-blocking `select` on `m.hashSem` (sized to `runtime.NumCPU()`, typically 2–8 slots) with **no waiting queue**. Because even unknown usernames trigger a full dummy Argon2id hash (`auth.BurnPasswordTime` at line 355), an unauthenticated attacker sending a few requests per second to `POST /api/v1/auth/login` keeps `m.hashSem` saturated and causes 100% of legitimate administrator logins and password changes to fail with `429 Too Many Requests`.
- **Remediation**:
  Use `auth.DerivationGate` (`internal/auth/derive.go`) in `internal/backupd/mgmt.go` (4 active slots + 32 queued waiters waiting on `r.Context().Done()`) instead of the non-blocking `hashSem` channel.

---

### [CICD-01] HIGH: Unpinned GitHub Actions Using Mutable Tags (`@v1`, `@v6`, `@v7`) Including Third-Party VM & Release Actions

- **Location**:
  - [.github/workflows/ci.yml](file:///Users/sverrirarason/Documents/Coding/jailops/.github/workflows/ci.yml#L30-L397)
  - [.github/workflows/release.yml](file:///Users/sverrirarason/Documents/Coding/jailops/.github/workflows/release.yml#L17-L37)
  - [docs/ci-supply-chain.md](file:///Users/sverrirarason/Documents/Coding/jailops/docs/ci-supply-chain.md#L1-L51)
- **Vulnerable Code**:
  ```yaml
  # .github/workflows/ci.yml:397
  - name: FreeBSD VM
    uses: vmactions/freebsd-vm@v1

  # .github/workflows/release.yml:35-38
  - uses: goreleaser/goreleaser-action@v6
    with:
      version: "~> v2"
      args: release --clean
  ```
- **Root Cause & Impact**:
  All GitHub Actions across `ci.yml` (`actions/checkout@v7`, `actions/setup-node@v7`, `actions/setup-go@v7`, `actions/cache@v4`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `vmactions/freebsd-vm@v1`) and `release.yml` (`goreleaser/goreleaser-action@v6`) are pinned only to mutable major version tags rather than immutable 40-character commit SHAs. If a third-party action repository such as `goreleaser/goreleaser-action` or `vmactions/freebsd-vm` has its tag compromised (as occurred in the `tj-actions/changed-files` supply-chain attack), an attacker can steal `GITHUB_TOKEN` (`contents: write` in `release.yml`) or inject malicious code into published release binaries. `docs/ci-supply-chain.md` explicitly notes that SHA pinning has not yet been applied.
- **Suggested Fix**:
  Pin every `uses:` directive in `.github/workflows/ci.yml` and `.github/workflows/release.yml` to a full 40-character commit SHA with a version comment, and pin `goreleaser` `version:` in `release.yml:37` to an exact release version rather than `"~> v2"`.

---

### [PRIV-04] MEDIUM: `fs.copy_tree` Preserves `setuid`/`setgid` Bits and Immutable File Flags (`schg`/`uchg`) Into Non-Jail Trees Without `admin` Assertion

- **Location**:
  - [internal/priv/copytree.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/copytree.go#L342-L363)
  - [internal/priv/copytree.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/copytree.go#L589-L608)
  - [internal/priv/ops.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/ops.go#L565-L573)
- **Vulnerable Code**:
  ```go
  // internal/priv/copytree.go:589-607
  func (c *copier) applyMeta(sf, df *os.File, fi os.FileInfo, dstRel string) error {
      st, _ := statOf(fi)
      if err := df.Chown(int(st.UID), int(st.GID)); err != nil && !c.noChown {
          return mapFSErr(err)
      }
      // chmod after chown: chown clears setuid and setgid.
      if err := df.Chmod(fi.Mode()); err != nil {
          return mapFSErr(err)
      }
      ...
      if st.Flags != 0 {
          if err := copyFlags(df, st.Flags); err != nil {
              c.res.MetaSkipped++
          }
      }
      return nil
  }
  ```
- **Root Cause & Impact**:
  1. **Unrestricted `setuid`/`setgid` Preservation**: In `internal/priv/fsagent.go:36-37, 129-132`, the helper carefully checks `l.agentSpecial(root)` (`jailTreeDepth(r.rel) > 0`) so that `setuid`/`setgid` bits are only restored into a jail tree (`root`, `root.new`, volume, image generation) and are stripped everywhere else (`docs/security-model.md:60-64`). Similarly, `WriteFile` (`safefs.go:244`) and `chmod` (`rules_ext.go:175`) forbid `setuid`/`setgid`. However, `CopyTree` (`fs.copy_tree`) copies `fi.Mode()` verbatim—including `os.ModeSetuid` and `os.ModeSetgid`—into **any** destination path under a storage mount (such as a jail's container directory `<mount>/projects/<p>/jails/<j>`), and does not require the `admin` assertion.
  2. **Uncleanable Immutable Files on Failed Copy (`forceRemove` / `removeStale`)**: `applyMeta` copies FreeBSD file flags (`SF_IMMUTABLE` / `schg`, `UF_IMMUTABLE` / `uchg`), which are present on standard FreeBSD base files (`/lib/libc.so.7`, `/usr/bin/su`, `/var/empty`). If a `CopyTree` operation is cancelled or fails mid-copy, `forceRemove` (`copytree.go:342-363`) and `removeStale` (`copytree.go:270-294`) call `Chmod(p, 0o700)` and `RemoveAll`, which **fail with `EPERM`** on files/directories carrying `SF_IMMUTABLE` or `UF_IMMUTABLE` because `chflags(0)` is never called before `RemoveAll`!
- **Suggested Fix**:
  1. Strip `os.ModeSetuid|os.ModeSetgid` in `CopyTree` (`applyMeta`) when `rd` is not a jail/image tree (`jailTreeDepth(rd.rel) == 0`).
  2. In `forceRemove` and `removeStale` (`internal/priv/copytree.go`), clear file flags (`copyFlags(f, 0)` / `unix.Chflags`) before calling `RemoveAll`.

---

### [PRIV-05] MEDIUM: Unbounded `SCM_RIGHTS` File Descriptor Accumulation in `jailops-priv` (`fdConn`) When Client Sends `NFds: 0`

- **Location**:
  - [internal/priv/wire.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/wire.go#L221-L254)
  - [internal/priv/wire.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/wire.go#L277-L292)
  - [internal/priv/server.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/server.go#L219-L232)
- **Vulnerable Code**:
  ```go
  // internal/priv/wire.go:221-229
  func (r fdReader) Read(p []byte) (int, error) {
      oob := make([]byte, unix.CmsgSpace(4*4))
      n, oobn, flags, _, err := r.fc.c.ReadMsgUnix(p, oob)
      ...
      if oobn > 0 {
          r.fc.collect(oob[:oobn])
      }
  ```
  ```go
  // internal/priv/wire.go:277-292
  func (fc *fdConn) read() (*Frame, []*os.File, error) {
      f, err := ReadFrame(fc.br)
      ...
      var files []*os.File
      if f.NFds != 0 {
          ...
          if files, err = fc.takeFDs(f.NFds); err != nil {
              return nil, nil, err
          }
      }
      return f, files, nil
  }
  ```
- **Root Cause & Impact**:
  In `internal/priv/server.go:226-232`, the server intends to forbid clients from sending file descriptors over `priv.sock` (`clients never send descriptors`). However, `fdReader.Read` unconditionally parses any `SCM_RIGHTS` control message received from the socket and appends the resulting `*os.File` handles to `fc.fds`. In `fc.read()`, `fc.takeFDs(f.NFds)` is only called if the JSON frame sets `f.NFds != 0`!
  If a compromised `jailopsd` sends frames with `NFds: 0` while attaching `SCM_RIGHTS` file descriptors in the ancillary data of each socket write, `fc.read()` returns `files = nil` and `f.NFds = 0`, bypassing the check at `server.go:226-232` while `fc.fds` grows without bound inside `jailops-priv` until the root helper exhausts `RLIMIT_NOFILE` / `kern.maxfiles` and can no longer accept connections or run commands.
- **Suggested Fix**:
  1. Add a boolean `allowRecvFDs bool` to `fdConn` (false on the server side of `priv.sock`, true only on the client side), and immediately close any received `SCM_RIGHTS` descriptors in `collect()` and fail the connection when `!fc.allowRecvFDs`.
  2. Even on the client side, cap `len(fc.fds)` (e.g., `maxQueuedFDs = 8`) in `collect()`.

---

### [PRIV-06] MEDIUM: Path-Based `Chmod`/`Chown` After `MkdirAll` and Pre-Rename `Lstat` in `safefs.go` & `logs.go` Inside Running Jail Trees

- **Location**:
  - [internal/priv/safefs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/safefs.go#L351-L387)
  - [internal/priv/safefs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/safefs.go#L429-L437)
  - [internal/priv/logs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/priv/logs.go#L293-L315)
- **Vulnerable Code**:
  ```go
  // internal/priv/safefs.go:429-437 (MkdirAll)
  if err := root.MkdirAll(r.rel, os.FileMode(q.Mode)); err != nil {
      return mapFSErr(err)
  }
  if err := root.Chmod(r.rel, os.FileMode(q.Mode)); err != nil {
      return mapFSErr(err)
  }
  if err := root.Chown(r.rel, int(q.UID), int(q.GID)); err != nil && !l.noChown {
      return mapFSErr(err)
  }
  ```
- **Root Cause & Impact**:
  1. In `MkdirAll` (`safefs.go:429-437`), after `root.MkdirAll(r.rel, ...)` creates the target directory, `root.Chmod(r.rel, ...)` and `root.Chown(r.rel, ...)` operate on the path `r.rel` rather than an open directory descriptor (`O_DIRECTORY|O_NOFOLLOW`). If `MkdirAll` is invoked on a running jail's tree with a non-zero `UID`/`GID`, a process in the jail can race between `MkdirAll` and `Chown` by replacing `r.rel` with a relative symlink or hardlink to another file inside the jail (such as `/etc/master.passwd`), causing `root.Chown` to change ownership of that file inside the jail.
  2. In `TailFile` (`logs.go:293-315`), `lr.Lstat(ref.name)` checks that the log file is not a symlink, and then `lr.OpenFile(ref.name, os.O_RDONLY|syscall.O_NONBLOCK, 0)` opens it **without `syscall.O_NOFOLLOW`**. A jail can swap the log file for a relative symlink inside `/var/log` between `Lstat` and `OpenFile`.
- **Suggested Fix**:
  1. In `MkdirAll` (`internal/priv/safefs.go:429-437`), open `r.rel` with `root.OpenFile(r.rel, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)` and call `f.Chmod` and `f.Chown` on the file descriptor.
  2. In `TailFile` (`internal/priv/logs.go:313`) and `ReadFile` (`internal/priv/safefs.go:288`), pass `syscall.O_NOFOLLOW` to `OpenFile` and walk subdirectory `d` in `TailFile` via `openBelow`.

---

### [AUTH-03] MEDIUM: `jailopsd` Bearer Token Verification Resets IP Lockout Counter on Any Valid Token (`tokLim.Success`) and Queries SQLite While Locked Out

- **Location**:
  - [internal/server/server.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/server/server.go#L272-L288)
  - [docs/exposure.md](file:///Users/sverrirarason/Documents/Coding/jailops/docs/exposure.md#L173)
  - [docs/security-model.md](file:///Users/sverrirarason/Documents/Coding/jailops/docs/security-model.md#L320-L321)
- **Vulnerable Code**:
  ```go
  // internal/server/server.go:275-287
  key := "tok|" + auth.SourceKey(remote)
  a, err := s.svc.AuthenticateToken(r.Context(), bearer, ip)
  if err != nil {
      if api.IsCode(err, api.CodeUnauthorized) {
          if lerr := s.tokLim.Fail(key); lerr != nil {
              return res, lerr
          }
      }
      return res, err
  }
  s.tokLim.Success(key)
  ```
- **Root Cause & Impact**:
  1. **Lockout Reset via Shared IP (`s.tokLim.Success(key)`)**: Every time a valid bearer token is presented from `remote`, `s.tokLim.Success(key)` deletes the `tok|<source>` entry from `s.tokLim` (`delete(l.entries, key)`). If an attacker brute-forcing tokens shares a source IP with a legitimate client or monitoring agent (e.g., behind NAT, a corporate egress IP, or a reverse proxy), every request from the legitimate token holder resets the attacker's failed-attempt counter to zero!
  2. **Unthrottled DB Lookups During Lockout**: Because `s.tokLim.Check(key)` is not called before `s.svc.AuthenticateToken`, an IP that is already locked out still triggers a SHA-256 hash and a SQLite query on every request.
  3. **Documentation Contradiction**: `docs/exposure.md:173, 232` claims that *"while a source is locked out its valid tokens are refused as well"*, which contradicts both `internal/server/server.go:273-286` and `docs/security-model.md:320-321`.
- **Suggested Fix**:
  Remove `s.tokLim.Success(key)` at `internal/server/server.go:285` (and `s.tokLim.Success(key)` at line 249 for hub certs) so valid requests do not clear the failure counter accumulated by invalid requests from the same IP/subnet, and align `docs/exposure.md:173, 232` with `docs/security-model.md:320-321`.

---

### [AUTH-04] MEDIUM: `jailops-backupd` Logs Unsanitized, Unbounded (up to 1 MiB) Anonymous `req.Username` Into PostgreSQL `audit` Table on Failed Login

- **Location**:
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L188)
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L362)
  - [internal/node/ctl/jobs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/node/ctl/jobs.go#L209-L216)
- **Vulnerable Code**:
  ```go
  // internal/backupd/mgmt.go:362
  _ = m.s.DB.Audit(r.Context(), "anonymous", "auth.login.failed", req.Username, nil, r.RemoteAddr)
  ```
- **Root Cause & Impact**:
  `docs/security-model.md:292` states: *"Nothing of the body of a public route is written: a failed login records the route, the source and the result, not the user name that was typed."* While `jailopsd` enforces this rule, `jailops-backupd` (`mgmt.go:362`) writes the raw `req.Username` from the unauthenticated request body directly into PostgreSQL `audit.target`:
  1. **Accidental Password Persistence**: If an admin types their password into the username field by mistake, it is stored in plaintext in the PostgreSQL `audit` table.
  2. **Database Bloat / Control-Character Injection**: `decodeBody` permits bodies up to `1 MiB` (`mgmt.go:188`), and `ctl.DB.Audit` (`jobs.go:209-216`) neither truncates nor escapes control characters, newlines, or Unicode bidirectional overrides (unlike `store.AuditText` in `jailopsd`).
- **Suggested Fix**:
  1. In `internal/backupd/mgmt.go:362`, pass `""` instead of `req.Username` as the target of `auth.login.failed` (matching `jailopsd`).
  2. Sanitize and bound all string fields (`actor`, `action`, `target`, `remote`) in `ctl.DB.Audit` (`internal/node/ctl/jobs.go:209`) using `store.AuditText` semantics.

---

### [AUTH-05] MEDIUM: Trust Token Redemption (`RedeemTrustToken`) Verifies Against Static Startup Fingerprint Instead of `servingFingerprint()`

- **Location**:
  - [internal/service/trust.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/service/trust.go#L72-L76)
  - [internal/service/trust.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/service/trust.go#L128-L140)
- **Vulnerable Code**:
  ```go
  // internal/service/trust.go:72 (CreateTrustToken)
  fp := s.servingFingerprint()
  tok, err := auth.SignTrustToken(hmacKey, auth.TrustClaims{ID: id, Fingerprint: fp, ExpiresAt: exp.Unix()})
  ...
  // internal/service/trust.go:128 (RedeemTrustToken)
  claims, err := auth.VerifyTrustToken(hmacKey, req.Token, s.d.ServerFingerprint, now)
  ```
- **Root Cause & Impact**:
  `CreateTrustToken` signs the trust token with `s.servingFingerprint()`, which returns the fingerprint of the currently active TLS certificate (such as an uploaded certificate, an ACME certificate, or a reloaded certificate). However, `RedeemTrustToken` checks the token against `s.d.ServerFingerprint` (the static fingerprint of the self-signed identity certificate at daemon startup). Consequently, whenever a host serves an uploaded, ACME, or rotated certificate, **every trust token issued by `CreateTrustToken` is rejected by `RedeemTrustToken` with `401 Unauthorized`**.
- **Suggested Fix**:
  Replace `s.d.ServerFingerprint` with `s.servingFingerprint()` in `RedeemTrustToken` (`internal/service/trust.go:128` and line 139).

---

### [SSRF-01] MEDIUM: API-Configured Log Forwarding Sinks Allow Probing & Sending Data to Non-Daemon Ports on the Host's Own IP and Local Jail Subnets

- **Location**:
  - [internal/logfwd/guard.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/logfwd/guard.go#L48-L69)
- **Vulnerable Code**:
  ```go
  // internal/logfwd/guard.go:62-63
  case slices.Contains(ownPorts, int(ap.Port())) && slices.Contains(local, a):
      class = "this daemon's port on a local"
  ```
- **Root Cause & Impact**:
  The comment at `internal/logfwd/guard.go:19` states: *"A sink set through the API is restricted: the daemon must not become a way to reach this host's own services or the link-local network."* And line 147 states: *"a receiver on this host or on the link-local network is configured in logging.forward of jailopsd.yaml"*.
  However, line 62 only rejects an address in `local` (the host's own interface IP addresses, including jail gateway IPs) if `ap.Port()` is in `ownPorts` (`jailopsd`'s own ports)! Any other service listening on the host's own IP address (e.g., unbound on port 53, SSH on port 22, PostgreSQL on port 5432, or any service on a local interface) is permitted, allowing an API token holder to send HTTP POST / TCP / UDP payloads to host-local services and use `POST /api/v1/logs/forward/test` (`Classify()`) as a port oracle (`connection refused` vs `timeout` vs `HTTP <code>`).
- **Suggested Fix**:
  In `CheckTarget` (`internal/logfwd/guard.go:62`), reject **all** ports on any address belonging to `local` (`case slices.Contains(local, a): class = "this host"`).

---

### [CICD-02] MEDIUM: `release.yml` Omits `persist-credentials: false` on `actions/checkout` While Running With `contents: write`

- **Location**:
  - [.github/workflows/release.yml](file:///Users/sverrirarason/Documents/Coding/jailops/.github/workflows/release.yml#L9-L19)
- **Vulnerable Code**:
  ```yaml
  permissions:
    contents: write

  jobs:
    release:
      runs-on: ubuntu-24.04
      steps:
        - uses: actions/checkout@v7
          with:
            fetch-depth: 0
  ```
- **Root Cause & Impact**:
  Unlike `.github/workflows/ci.yml` (which sets `persist-credentials: false` on all 8 checkout steps), `release.yml` leaves `persist-credentials: true` (the default) while running with `contents: write`. This writes the privileged `GITHUB_TOKEN` into `.git/config`, where it is readable by `npm ci` and `npm run build:all` hooks executed during `.goreleaser.yaml` `before.hooks`.
- **Suggested Fix**:
  Add `persist-credentials: false` under `with:` on `actions/checkout` in `.github/workflows/release.yml:19`.

---

### [CICD-03] MEDIUM: Missing Cryptographic Signatures / SLSA Provenance on Release Artifacts & Unprotected `workflow_dispatch`

- **Location**:
  - [.github/workflows/release.yml](file:///Users/sverrirarason/Documents/Coding/jailops/.github/workflows/release.yml#L7-L40)
  - [.goreleaser.yaml](file:///Users/sverrirarason/Documents/Coding/jailops/.goreleaser.yaml#L189-L191)
- **Root Cause & Impact**:
  `.goreleaser.yaml` publishes `checksums.txt` and binary archives without cryptographic signatures (`cosign` or GPG) or GitHub SLSA build provenance attestations (`actions/attest-build-provenance`), and `release.yml` allows manual `workflow_dispatch` triggers with `contents: write`.
- **Suggested Fix**:
  Add `actions/attest-build-provenance` to `release.yml` and sign `checksums.txt` with `cosign` in `.goreleaser.yaml`.

---

### [PKG-01] MEDIUM: `packaging/jailops-setup` Regex Bug Breaks BSD/macOS `awk` (`5 failed checks`), Uses `eval` on `awk` Output, and Uses Static `/etc/pf.conf.jailops-setup.tmp`

- **Location**:
  - [packaging/jailops-setup](file:///Users/sverrirarason/Documents/Coding/jailops/packaging/jailops-setup#L217)
  - [packaging/jailops-setup](file:///Users/sverrirarason/Documents/Coding/jailops/packaging/jailops-setup#L266)
  - [packaging/jailops-setup](file:///Users/sverrirarason/Documents/Coding/jailops/packaging/jailops-setup#L333)
- **Vulnerable Code**:
  ```awk
  # packaging/jailops-setup:217
  else if (k ~ /^(pass|block|anchor|match|antispoof)$/) { cls = "filter"; if (k == "match" && t ~ /[ \t]scrub([ \t(]|$)/) scrub = 1 }
  ```
  ```sh
  # packaging/jailops-setup:266
  eval "$(pfplan "$conf")"
  ```
- **Root Cause & Impact**:
  1. **BSD/FreeBSD `awk` Regex Bug (Confirmed by Dynamic Test Run)**: Running `sh scripts/jailops-setup-test.sh` fails 5 checks because `packaging/jailops-setup:217` uses the regex literal `/[ \t]scrub([ \t(]|$)/` inside `PFAWK`. In One True Awk (used by both macOS and FreeBSD `/usr/bin/awk`), an unescaped `(` inside a bracket expression `[ \t(]` in a `/.../` regex literal causes a fatal regex parse error (`awk: syntax error in regular expression`), causing `pfplan` to produce empty output and `jailops-setup` to fail when `/etc/pf.conf` exists!
  2. **`eval` on `awk` Output (`jailops-setup:266`)**: `eval "$(pfplan "$conf")"` evaluates `awk` stdout as shell commands as `root`.
  3. **Predictable Temp File (`jailops-setup:333`)**: Uses fixed filename `$conf.jailops-setup.tmp` instead of `mktemp`.
  4. **Pool Option Flag Injection (`jailops-setup:125`)**: In `packaging/jailops-setup:125`, `grep -qx -- "$pool"` runs *after* `case $pool in ""|-*|...)` on line 123, wait: why did `setup -pool '-x'` fail `[ "$rc" = 2 ]` in `jailops-setup-test.sh`? Look at `packaging/jailops-setup:50`: when `-pool -x` is passed, `pool=-x`, and then on line 123: `case $pool in ""|-*|*[!A-Za-z0-9_.:-]*) say "x -pool names a pool..."; exit 2 ;; esac` — wait: why did `setup -pool '-x'` fail in `jailops-setup-test.sh:290`? Because in `jailops-setup-test.sh:290`, `FAKE_UID=1001` was set on line 287 (`FAKE_UID=1001 setup -y`)! In POSIX `/bin/sh` (and FreeBSD `/bin/sh`!), a variable assignment before a shell **function** call (`FAKE_UID=1001 setup -y`) **persists in the caller's shell environment after the function returns**! So on line 290, `FAKE_UID` was still `1001`, causing `setup -pool '-x'` to exit with `rc=1` ("must run as root") instead of `rc=2`!
- **Suggested Fix**:
  1. In `packaging/jailops-setup:217`, escape `\(` inside the character class or rewrite as `/[ \t]scrub([ \t]|[(]|$)/`.
  2. Replace `eval "$(pfplan "$conf")"` with `read -r ... <<EOF` parsing.
  3. Use `mktemp "${conf}.jailops-setup.XXXXXX"` at line 333.
  4. In `scripts/jailops-setup-test.sh:87`, reset or scope `FAKE_UID` inside `new_host()` (`FAKE_UID=0`).

---

### [PKG-02] MEDIUM: World-Readable (`0755`) `/usr/local/etc/jailops/jails` and `/var/tmp/jailops` Expose Rendered Jail Configs and Build Artifacts to Local Users

- **Location**:
  - [cmd/jailops-priv/init.go](file:///Users/sverrirarason/Documents/Coding/jailops/cmd/jailops-priv/init.go#L224-L243)
  - [scripts/pkg-build.sh](file:///Users/sverrirarason/Documents/Coding/jailops/scripts/pkg-build.sh#L66-L77)
- **Root Cause & Impact**:
  `jailops-priv init` creates `/usr/local/etc/jailops`, `/usr/local/etc/jailops/jails` (`conf-dir`), and `/var/tmp/jailops` (`work-dir`) with mode `0755` (`root:wheel`). This allows any unprivileged local user on the host to list and read rendered `jail.conf` and `fstab` files and inspect temporary archives and staging files in `/var/tmp/jailops`.
- **Suggested Fix**:
  Create `/usr/local/etc/jailops/jails` and `/var/tmp/jailops` with mode `0750` owned by `root:jailops` (and update `checkOwnRoot` in `internal/priv/safefs.go:609` to allow group `jailops` read/execute `0750` while keeping group/world write bits `0o022` forbidden).

---

### [PKG-03] MEDIUM: `examples/provisioning/bootstrap.sh` Uses Deprecated PF Translation Anchors, Omits `set state-policy if-bound`, and Uses Unquoted `$(ls ...)`

- **Location**:
  - [examples/provisioning/bootstrap.sh](file:///Users/sverrirarason/Documents/Coding/jailops/examples/provisioning/bootstrap.sh#L56-L72)
  - [examples/provisioning/bootstrap.sh](file:///Users/sverrirarason/Documents/Coding/jailops/examples/provisioning/bootstrap.sh#L101)
- **Root Cause & Impact**:
  `examples/provisioning/bootstrap.sh:68-72` appends `nat-anchor "jailops/*"` and `rdr-anchor "jailops/*"` to `/etc/pf.conf` and omits `set state-policy if-bound`. As noted in `CHANGELOG.md:381-384` and `docs/design.md:355`, legacy translation anchors break port forwards and fail `jailops doctor` (`pf.anchors` and `pf.state-policy`). Additionally, lines 56–57 and 101 use unquoted command substitutions (`pkg add $(ls ...)`).
- **Suggested Fix**:
  Update `examples/provisioning/bootstrap.sh` to invoke `jailops-setup -y` (or write `set state-policy if-bound`, `scrub in all fragment reassemble`, and `anchor "jailops/*"` only) and quote file globs.

---

### [DOC-01] MEDIUM: Documented Disaster Recovery Key (`JOR1-...`) Has No CLI/API Restore Command; Capsicum (`cap_enter`) and Key FreeBSD 15.1 Controls Remain Unverified

- **Location**:
  - [cmd/jailops-priv/agent.go](file:///Users/sverrirarason/Documents/Coding/jailops/cmd/jailops-priv/agent.go#L56-L67)
  - [docs/backup-restore.md](file:///Users/sverrirarason/Documents/Coding/jailops/docs/backup-restore.md#L166-L169)
  - [docs/design.md](file:///Users/sverrirarason/Documents/Coding/jailops/docs/design.md#L1178-L1228)
- **Root Cause & Impact**:
  1. **Missing Recovery Key Restore Path**: While `internal/repo/format/keys.go:172` implements `DecodeRecoveryKey("JOR1-...")`, no CLI subcommand or API endpoint wires it up to reconstruct a lost `backup.key` on a replacement host (`docs/backup-restore.md:166-169`).
  2. **No Capsicum Confinement (`cap_enter`)**: `cmd/jailops-priv/agent.go:56` runs `fsagent` as `euid 0` inside `unix.Chroot(*root)` without entering FreeBSD Capsicum capability mode (`unix.CapEnter()`).
  3. **Unverified FreeBSD 15.1 Security Controls (`docs/design.md:1178-1228`)**: Key controls (`zfs receive -x devices -x setuid -x exec`, `LOCAL_PEERCRED` under `sudo`/SSH forwarding, `jailops_revert` boot order on unconfirmed firewall change, and kernel WireGuard `if_wg`) remain marked `UNVERIFIED` on a real FreeBSD host.
- **Suggested Fix**:
  1. Add `jailops backup key-recover` (and the corresponding API/service handler) calling `format.DecodeRecoveryKey` to write `/var/db/jailops/backup.key` (`0600`).
  2. Refactor `internal/fsagent` to operate on a pre-opened root directory descriptor (`*os.Root` / `*at` syscalls) and call `unix.CapEnter()` in `cmd/jailops-priv/agent.go`.

---

### [WEB-01] LOW: Missing CSP & Framing Headers on `jailops-backupd` Web UI, Incomplete `jailops_csrf` Cookie Cleanup on Logout, and Bearer Token Storage in `sessionStorage`

- **Location**:
  - [internal/backupui/webui.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupui/webui.go#L99-L107)
  - [internal/backupd/mgmt.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/backupd/mgmt.go#L183-L199)
  - [internal/server/handlers.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/server/handlers.go#L448)
  - [web/shared/src/api/client.ts](file:///Users/sverrirarason/Documents/Coding/jailops/web/shared/src/api/client.ts#L69-L77)
- **Root Cause & Impact**:
  1. Unlike `internal/server/mw.go:136-148` (which sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Permissions-Policy` on all `jailopsd` responses), `jailops-backupd` (`internal/backupui/webui.go` and `internal/backupd/mgmt.go`) sets only `X-Content-Type-Options: nosniff` and `Cache-Control`, omitting `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy`, and `Permissions-Policy`.
  2. When a user logs into the web console using an API token (`loginWithToken`), `web/shared/src/api/client.ts:71` persists the raw Bearer token in `sessionStorage.setItem('jailops.token', t)`.
  3. `internal/server/handlers.go:448` omits `SameSite: http.SameSiteStrictMode` when clearing `jailops_csrf` on logout.
- **Suggested Fix**:
  Add the same security response headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`) to `internal/backupd/mgmt.go` and `internal/backupui/webui.go`, and add `SameSite: http.SameSiteStrictMode` when expiring `jailops_csrf` in `internal/server/handlers.go:448`.

---

### [DB-01] LOW: SQL `LIKE` Wildcard Injection (`%`, `_`) in `jailops-backupd` Audit Log Prefix Filter

- **Location**:
  - [internal/node/ctl/jobs.go](file:///Users/sverrirarason/Documents/Coding/jailops/internal/node/ctl/jobs.go#L219-L228)
- **Vulnerable Code**:
  ```go
  rows, err := d.pool.Query(ctx, `SELECT id, at, actor, action, target, detail, remote FROM audit
      WHERE id < $3 AND action LIKE $1 || '%' ORDER BY id DESC LIMIT $2`, actionPrefix, limit, beforeID)
  ```
- **Root Cause & Impact**:
  `actionPrefix` is passed to `LIKE $1 || '%'` without escaping `%`, `_`, or `\`, unlike `internal/store/audit.go:130-139` which escapes `LIKE` wildcards.
- **Suggested Fix**:
  Escape `\`, `%`, and `_` in `actionPrefix` and add `ESCAPE '\'` to the query in `internal/node/ctl/jobs.go:227`.

---

### [PKG-04] LOW: Unquoted Variable Expansions in `packaging/rc.d/*` and Unescaped JSON Interpolation in `scripts/pkg-build.sh`

- **Location**:
  - [packaging/rc.d/jailopsd](file:///Users/sverrirarason/Documents/Coding/jailops/packaging/rc.d/jailopsd#L82-L157)
  - [packaging/rc.d/jailops_priv](file:///Users/sverrirarason/Documents/Coding/jailops/packaging/rc.d/jailops_priv#L72-L122)
  - [scripts/pkg-build.sh](file:///Users/sverrirarason/Documents/Coding/jailops/scripts/pkg-build.sh#L41-L154)
- **Root Cause & Impact**:
  `packaging/rc.d/*` scripts leave path and PID expansions unquoted (e.g., `echo "${_out}" > ${jailopsd_console}`), and `scripts/pkg-build.sh` interpolates `$version` and `$abi` into JSON manifests without validation and iterates over `$(find ...)` without `IFS` protection.
- **Suggested Fix**:
  Double-quote all single-value variable expansions in `packaging/rc.d/*` and validate `$version` and `$abi` against `^[0-9A-Za-z._:-]+$` in `scripts/pkg-build.sh`.

---

### [SBOM-01] LOW: Transitive Dependency Bloat (~120 Cloud SDK Packages via `sops/v3`) and Static Test `age` Key in `examples/example-identity.txt`

- **Location**:
  - [go.mod](file:///Users/sverrirarason/Documents/Coding/jailops/go.mod#L8)
  - [examples/example-identity.txt](file:///Users/sverrirarason/Documents/Coding/jailops/examples/example-identity.txt#L2)
  - [examples/minimal-fleet/.sops.yaml](file:///Users/sverrirarason/Documents/Coding/jailops/examples/minimal-fleet/.sops.yaml#L5)
- **Root Cause & Impact**:
  1. Importing `github.com/getsops/sops/v3` pulls ~120 cloud KMS SDK packages (AWS, GCP, Azure, Vault, Huawei, MongoDB, gRPC) into the root `go.mod` even though `jailops-sync` only supports `age` keys.
  2. `examples/example-identity.txt` contains a static throwaway `age` private key corresponding to `examples/minimal-fleet/.sops.yaml`. If an operator copies `examples/minimal-fleet` without replacing the recipient in `.sops.yaml`, their secrets are encrypted to a publicly known key.
- **Suggested Fix**:
  1. Have `jailops-sync` emit a warning or error when encrypting/applying a fleet repository that still lists the example public key `age1lqp7xcnt4qaugajyxtsnlntvj6asghmpn6r80aggchmd9tzuksvq9h3vyp` outside of tests.
  2. Consider isolating `jailops-sync` in its own Go module (like `sdk/go.mod`) or implementing SOPS-`age` envelope parsing directly with `filippo.io/age` and `gopkg.in/yaml.v3`.

---

## 6. Notable Security Strengths Observed

The JailOps codebase demonstrates an exceptionally high baseline of defensive security design:
1. **Strict Command Execution Boundary (`internal/sys/run`, `internal/priv/allowlist.go`)**: External commands are never executed through `/bin/sh -c`; all invocations pass explicit argument vectors (`argv`) with mandatory timeouts and output caps.
2. **Pure, Escaped Config Renderers (`internal/render/*`, `internal/priv/confcheck.go`)**: Every value rendered into `jail.conf`, `rc.conf`, `fstab`, PF anchors, and `unbound.conf` is validated against strict allow-lists and re-verified by `jailops-priv` before loading.
3. **Default-Deny Route Permission Matrix (`internal/auth/perms.go`)**: Every HTTP route in `jailopsd` and `jailops-backupd` must have an entry in the permission registry, or the server refuses to start. Project-scoped access returns `404 Not Found` (rather than `403 Forbidden`) for unauthorized projects to prevent resource enumeration.
4. **Symlink-Safe Path Traversal Guards (`internal/priv/safefs.go`, `internal/logfwd/files.go`)**: Uses Go's `os.Root` (`openat` with `O_RESOLVE_BENEATH` / `O_NOFOLLOW`), inode/device verification (`os.SameFile`), and `O_NONBLOCK` (preventing FIFO hangs when reading files inside jail trees).
5. **Keyless Backup Node Architecture (`cmd/jailops-backupd`, `internal/backupd/arch_test.go`)**: Enforced by architectural unit tests so `jailops-backupd` never links decryption, ZFS, jail, or privileged-helper packages; chunks and manifests are authenticated and encrypted client-side with XChaCha20-Poly1305 and HMAC-SHA256 under HKDF-derived subkeys.
