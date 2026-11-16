// Canned catalog and jail logs for `?demo`. The definitions follow the catalog (internal/apps/testdata/catalog); one more,
// memcached, is a definition of the host's own directory (source local), and one is invalid so the catalog shows that
// state. Logs get timestamps relative to now and grow while they are followed.
import type { App, AppDetail, AppSummary, JailLogFile, JailLogRead } from '@jailops/shared/api/types'

const hash = (name: string) => 'sha256:' + Array.from({ length: 64 }, (_, i) => '0123456789abcdef'[(name.charCodeAt(i % name.length) * (i + 7)) % 16]).join('')

// A plain geometric mark (not a product logo), so the catalog shows the icon path as well as the monogram.
const svg = (body: string) => 'data:image/svg+xml;base64,' + btoa(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${body}</svg>`)
const ICONS: Record<string, string> = {
  nginx: svg('<path d="M32 4 56 18v28L32 60 8 46V18z" fill="#1f8f4e"/><path d="M23 44V20l18 24V20" fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round"/>'),
  prometheus: svg('<circle cx="32" cy="32" r="28" fill="#d8572a"/><path d="M20 40h24M22 46h20M32 14c6 8 10 12 6 22h-12c-4-10 0-14 6-22z" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"/>'),
  // the icons the catalog ships with these three
  isms: svg('<path d="M32 4 54 12v18c0 14-9 24-22 30C19 54 10 44 10 30V12z" fill="#2d5f8b"/><path d="M22 32l7 7 13-15" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'),
  nsd: svg('<circle cx="32" cy="32" r="28" fill="#3b6e8f"/><path d="M32 4v56M4 32h56M32 4c-10 8-14 18-14 28s4 20 14 28M32 4c10 8 14 18 14 28s-4 20-14 28" fill="none" stroke="#fff" stroke-width="3"/>'),
  mail: svg('<rect x="6" y="14" width="52" height="36" rx="5" fill="#8b5a2d"/><path d="M8 17l24 19 24-19" fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"/>'),
}

const IMAGE = { os: 'freebsd', release_min: '15.1' }

export const definitions: App[] = [
  {
    version: 1, name: 'nginx', title: 'nginx', summary: 'Web server and reverse proxy, serving /usr/local/www.',
    description: 'nginx is a small, fast web server and reverse proxy. The package installs the\nserver with its dynamic modules and a default site under /usr/local/www/nginx-dist,\nwhich this definition copies to /usr/local/www/nginx, the root of the default\nconfiguration; the configuration lives in /usr/local/etc/nginx/nginx.conf and is checked\n(nginx -t) before every start and reload.\n',
    category: 'web', homepage: 'https://nginx.org/', license: 'BSD-2-Clause', icon: 'nginx.svg', image: IMAGE,
    packages: [{ name: 'nginx', repo: 'ports', version: '1.30.6,3' }],
    services: [{ name: 'nginx', start: true }],
    ports: [
      { name: 'http', port: 80, proto: 'tcp', description: 'HTTP, the default site.', expose: true },
      { name: 'https', port: 443, proto: 'tcp', description: 'HTTPS; not configured until a certificate and a server block are added.', expose: false },
    ],
    data: [{ path: '/usr/local/www', description: 'The sites; the default site is nginx, copied from nginx-dist.' }],
    config: [{ path: '/usr/local/etc/nginx/nginx.conf', description: "The server configuration; 'service nginx reload' applies most changes without a restart.", restart: 'nginx' }],
    logs: [
      { name: 'access', path: '/var/log/nginx/access.log', description: 'One line per request.' },
      { name: 'error', path: '/var/log/nginx/error.log', description: 'Errors and warnings of the server.' },
    ],
    setup: [['/bin/mkdir', '-p', '/usr/local/www/nginx'], ['/bin/cp', '-Rn', '/usr/local/www/nginx-dist/.', '/usr/local/www/nginx/']],
    health: { http: { port: 80, path: '/', status: 200 }, wait_seconds: 30 },
    resources: { memory: '256M', disk: '2G', cpu: '1' },
    notes: "Put the site under /usr/local/www and its server block in\n/usr/local/etc/nginx/nginx.conf; run 'service nginx reload' inside the jail to\napply a change. Add a certificate before enabling the https port.\n",
  },
  {
    version: 1, name: 'postgresql', title: 'PostgreSQL', summary: 'Relational database server, PostgreSQL 18 from the FreeBSD packages.',
    description: 'PostgreSQL is a relational database with transactions, replication and a large\nextension ecosystem. This definition installs the server package of the current\nmajor release, initialises a cluster under /var/db/postgres/data18 with UTF-8 and\nthe C collation (the port\'s defaults) and starts it.\n\nThe cluster listens on localhost only until listen_addresses in postgresql.conf\nand the client rules in pg_hba.conf are changed. The port logs to syslog.\n',
    category: 'database', homepage: 'https://www.postgresql.org/', license: 'PostgreSQL', image: IMAGE,
    packages: [{ name: 'postgresql18-server', repo: 'ports', version: '18.6' }],
    services: [{ name: 'postgresql', start: true }],
    ports: [{ name: 'postgres', port: 5432, proto: 'tcp', description: 'The SQL port; listens on localhost until listen_addresses is set.', expose: false }],
    data: [{ path: '/var/db/postgres', description: 'The cluster (data18) and the home of the postgres user.' }],
    config: [
      { path: '/var/db/postgres/data18/postgresql.conf', description: 'Server settings, including listen_addresses and logging.', restart: 'postgresql' },
      { path: '/var/db/postgres/data18/pg_hba.conf', description: 'Who may connect from where, and how they authenticate.', restart: 'postgresql' },
    ],
    logs: [{ name: 'server', path: '/var/log/messages', description: 'The port logs to syslog by default (log_destination in postgresql.conf).' }],
    setup: [['/usr/sbin/chown', 'postgres:postgres', '/var/db/postgres'], ['/usr/sbin/service', 'postgresql', 'initdb']],
    health: { exec: ['/usr/local/bin/pg_isready', '-U', 'postgres'], wait_seconds: 60 },
    resources: { memory: '1G', disk: '10G', cpu: '1' },
    access: { type: 'postgresql', port: 'postgres', service: 'postgresql', hba_file: '/var/db/postgres/data18/pg_hba.conf' },
    notes: "Connect from inside the jail with: jailops exec NAME -- su -l postgres -c psql\nThe jail accepts no connection from outside until you allow one:\njailops app allow NAME --from jail:web makes a role and a database for the jail\nweb, lets its address in and prints the connection string once.\n",
  },
  {
    version: 1, name: 'valkey', title: 'Valkey', summary: 'In-memory key-value store under the BSD license.',
    description: 'Valkey is a high-performance data structure server for key/value\nworkloads. The package ships\nthe server, the command line client and a sentinel; this definition runs the\nserver with the configuration the package installs.\n\nThe server binds 127.0.0.1 and ::1 with protected mode on until\n/usr/local/etc/valkey.conf is changed.\n',
    category: 'database', homepage: 'https://valkey.io/', license: 'BSD-3-Clause', image: IMAGE,
    packages: [{ name: 'valkey', repo: 'ports', version: '9.1.2' }],
    services: [{ name: 'valkey', start: true }],
    ports: [{ name: 'valkey', port: 6379, proto: 'tcp', description: 'The protocol port; bound to localhost until bind is changed.', expose: false }],
    data: [{ path: '/var/db/valkey', description: 'Snapshots and the append-only file.' }],
    config: [{ path: '/usr/local/etc/valkey.conf', description: 'The server configuration (bind, protected-mode, persistence).', restart: 'valkey' }],
    logs: [{ name: 'server', path: '/var/log/valkey/valkey.log', description: 'The server log.' }],
    setup: [['/usr/sbin/chown', 'valkey:valkey', '/var/db/valkey']],
    health: { exec: ['/usr/local/bin/valkey-cli', 'ping'], wait_seconds: 30 },
    resources: { memory: '512M', disk: '2G', cpu: '1' },
    notes: 'Talk to it from inside the jail with: jailops exec NAME -- valkey-cli\nTo reach it from other jails, set bind and requirepass in valkey.conf and\nrestart the service.\n',
  },
  {
    version: 1, name: 'forgejo', title: 'Forgejo', summary: 'Self-hosted git forge with issues, pull requests and CI hooks.',
    description: 'Forgejo is a compact, self-hosted software forge: git hosting, issues, pull\nrequests, wikis, packages and a web interface. The package runs it as the git\nuser under /var/db/forgejo with the configuration in\n/usr/local/etc/forgejo/conf/app.ini.\n\nThe installation leaves the configuration to the web installer: the first\nvisit to port 3000 asks for the database (SQLite under /var/db/forgejo works\nout of the box) and the first account, which becomes the administrator.\n',
    category: 'devops', homepage: 'https://forgejo.org/', license: 'MIT', image: IMAGE,
    packages: [{ name: 'forgejo16', repo: 'ports', version: '16.0.6_1' }],
    services: [{ name: 'forgejo', rc: { forgejo_configcheck_enable: 'NO' }, start: true }],
    ports: [{ name: 'http', port: 3000, proto: 'tcp', description: 'The web interface and the HTTP git endpoint.', expose: true }],
    data: [{ path: '/var/db/forgejo', description: 'Repositories, the SQLite database, attachments, indexes and sessions.' }],
    config: [{ path: '/usr/local/etc/forgejo/conf/app.ini', description: 'The configuration the web installer writes; secrets included, keep it private.', restart: 'forgejo' }],
    logs: [
      { name: 'app', path: '/var/log/forgejo', description: 'Log files, when the [log] section writes files.' },
      { name: 'syslog', path: '/var/log/daemon.log', description: 'What the service prints; daemon(8) sends it to syslog as daemon.info.' },
    ],
    setup: [['/bin/rm', '-f', '/usr/local/etc/forgejo/conf/app.ini'], ['/usr/sbin/chown', '-R', 'git:git', '/usr/local/etc/forgejo'], ['/usr/sbin/chown', '-R', 'git:git', '/var/db/forgejo', '/var/log/forgejo']],
    health: { tcp: 3000, wait_seconds: 60 },
    resources: { memory: '1G', disk: '10G', cpu: '1' },
    notes: "Open http://ADDRESS:3000/ to finish the setup in the browser: choose SQLite3\nwith /var/db/forgejo/forgejo.db, keep the repository root\n/var/db/forgejo/forgejo-repositories, set the server domain and base URL to\nthe address you reach the jail by, and register the first user, who becomes\nthe administrator. The installer writes app.ini; later changes to it need\n'service forgejo restart' inside the jail.\n",
  },
  {
    version: 1, name: 'prometheus', title: 'Prometheus', summary: 'Metrics collection, storage and alerting with PromQL.',
    description: 'Prometheus scrapes metrics from HTTP endpoints, stores them as time series\nand evaluates alerting rules. The package installs the current major release\nwith a configuration that scrapes Prometheus itself; scrape targets and rule\nfiles are added to /usr/local/etc/prometheus.yml.\n\nThe time series database lives under /var/db/prometheus. The web interface\nand the API are on port 9090.\n',
    category: 'monitoring', homepage: 'https://prometheus.io/', license: 'Apache-2.0', icon: 'prometheus.svg', image: IMAGE,
    packages: [{ name: 'prometheus3', repo: 'ports', version: '3.15.0_2' }],
    services: [{ name: 'prometheus', start: true }],
    ports: [{ name: 'http', port: 9090, proto: 'tcp', description: 'The web interface, the query API and /metrics.', expose: false }],
    data: [{ path: '/var/db/prometheus', description: 'The time series database (storage.tsdb.path).' }],
    config: [{ path: '/usr/local/etc/prometheus.yml', description: "Scrape targets, rule files and alertmanagers; 'service prometheus reload' applies a change.", restart: 'prometheus' }],
    logs: [{ name: 'syslog', path: '/var/log/daemon.log', description: 'The server log; daemon(8) sends it to syslog as daemon.info.' }],
    setup: [['/usr/sbin/chown', 'prometheus:prometheus', '/var/db/prometheus']],
    health: { http: { port: 9090, path: '/-/healthy', status: 200 }, wait_seconds: 60 },
    resources: { memory: '1G', disk: '20G', cpu: '1' },
    notes: 'Add scrape targets under scrape_configs in /usr/local/etc/prometheus.yml and\nrun \'service prometheus reload\' inside the jail. Retention defaults to 15\ndays; set prometheus_args="--storage.tsdb.retention.time=90d" in the jail\'s\nrc.conf to change it.\n',
  },
  {
    version: 1, name: "isms", title: "isms", summary: "Information security management platform with git-native documents; needs PostgreSQL.",
    description: "isms is an information security management system: policies, controls and\nevidence kept as git-native documents, collaboration through PostgreSQL, one\nbinary with the web interface embedded. The package comes from the JailOps\npackage repository and runs as the isms user with its data under\n/var/db/isms and its settings in /usr/local/etc/isms/server.env.\n\nThe installation does not configure or start it: isms needs a PostgreSQL\ndatabase, which this app does not contain, and a master secret that only the\noperator should create. The notes list the steps; the postgresql app of this\ncatalog provides the database.\n",
    category: "security", homepage: "https://github.com/unidoc/isms", license: "Apache-2.0", icon: "isms.svg", image: IMAGE,
    packages: [{ name: "isms", repo: "jailops", version: "0.8.1" }, { name: "openssh-portable", repo: "ports" }],
    services: [{ name: "isms", start: false }],
    ports: [{ name: "http", port: 8080, proto: "tcp", description: "The web interface and the API; put a TLS proxy in front.", expose: true }],
    data: [{ path: "/var/db/isms", description: "The per-organisation git repositories, file blobs, templates and the signing key." }],
    config: [{ path: "/usr/local/etc/isms/server.env", description: "KEY=VALUE settings with the database URL and the master secret; mode 0600, owner isms.", restart: "isms" }],
    logs: [{ name: "server", path: "/var/log/isms.log", description: "What the program prints, written by daemon(8)." }],
    setup: [
      ["/bin/mkdir", "-p", "/var/db/isms/private"],
      ["/usr/sbin/chown", "isms:isms", "/var/db/isms", "/var/db/isms/private", "/usr/local/etc/isms/server.env"],
      ["/bin/chmod", "0750", "/var/db/isms"],
      ["/bin/chmod", "0700", "/var/db/isms/private"],
      ["/bin/chmod", "0600", "/usr/local/etc/isms/server.env"],
    ],
    resources: { memory: "1G", disk: "10G", cpu: "1" },
    notes: "isms is enabled but not started. Until server.env is complete, a restart of\nthe jail starts it and it exits again every 5 seconds; /var/log/isms.log says\nwhy. Do these steps once (DB is a postgresql jail, ADDR this jail's address):\n1. In DB: jailops shell DB, then su -l postgres -c psql and run\n   CREATE ROLE isms LOGIN PASSWORD 'PW'; CREATE DATABASE isms OWNER isms;\n   Set listen_addresses = '*' in postgresql.conf, add to pg_hba.conf\n   host isms isms ADDR/32 scram-sha-256\n   and run service postgresql restart.\n2. In this jail (jailops shell NAME), edit /usr/local/etc/isms/server.env:\n   DATABASE_URL=\"postgres://isms:PW@DB_ADDRESS:5432/isms?sslmode=disable\",\n   ISMS_BASE_URL (the https URL users open) and ISMS_SIGNING_EMAIL.\n3. Set the master secret once and back it up; never change it later:\n   sed -i '' \"s|^ISMS_SECRET=.*|ISMS_SECRET=$(openssl rand -hex 32)|\" /usr/local/etc/isms/server.env\n4. Create the signing key (your ISMS_SIGNING_EMAIL as the comment):\n   su -m isms -c 'ssh-keygen -q -t ed25519 -N \"\" -C you@example.com -f /var/db/isms/private/isms_key'\n5. Apply the schema:\n   env ISMS_SERVER_ENV=/usr/local/etc/isms/server.env su -m isms -c '/usr/local/bin/isms server migrate'\n6. service isms start\nThe web interface is on port 8080; serve it over https through\nthe nginx app. A coming version wires apps together with jailops app allow\n(role, password and DATABASE_URL made for you); until then, these steps.\n",
  },
  {
    version: 1, name: "nsd", title: "NSD", summary: "Authoritative DNS server for your own zones, as a primary or a secondary.",
    description: "NSD is an authoritative-only DNS server: it answers for the zones it is\ngiven and does no recursion. It serves zone files, sends NOTIFY and\nprovides zone transfers to secondaries, and as a secondary requests the\nzones from a primary.\n\nThis definition writes a starter configuration with one example zone,\nexample.com, under /var/db/nsd/zones, checks it with nsd-checkconf and\nnsd-checkzone and starts the server on port 53, UDP and TCP. Replace the\nexample with your zones; the notes show the lines for a primary and for a\nsecondary.\n",
    category: "network", homepage: "https://nlnetlabs.nl/projects/nsd/about/", license: "BSD-3-Clause", icon: "nsd.svg", image: IMAGE,
    packages: [{ name: "nsd", repo: "ports", version: "4.15" }],
    services: [{ name: "nsd", start: true }],
    ports: [
      { name: "dns", port: 53, proto: "udp", description: "DNS queries over UDP.", expose: true },
      { name: "dns-tcp", port: 53, proto: "tcp", description: "DNS over TCP, large answers and zone transfers.", expose: true },
    ],
    data: [{ path: "/var/db/nsd", description: "Zone files (zones/), transferred zones and the state of the transfer daemon." }],
    config: [{ path: "/usr/local/etc/nsd/nsd.conf", description: "Server and zone settings; check with nsd-checkconf before a restart.", restart: "nsd" }],
    logs: [{ name: "daemon", path: "/var/log/daemon.log", description: "NSD logs to syslog (facility daemon) unless logfile is set." }],
    setup: [
      ["/bin/mkdir", "-p", "/var/db/nsd/zones", "/var/run/nsd"],
      ["/bin/sh", "-c", "f=/usr/local/etc/nsd/nsd.conf; [ -e $f ] || printf '%s\\n' '# Starter configuration of the nsd app; see its notes.' 'server:' '    username: nsd' '    database: \"\"' '    zonesdir: \"/var/db/nsd/zones\"' '    zonelistfile: \"/var/db/nsd/zone.list\"' '    xfrdfile: \"/var/db/nsd/xfrd.state\"' '    xfrdir: \"/var/db/nsd\"' '    hide-version: yes' '' 'remote-control:' '    control-enable: no' '' 'zone:' '    name: \"example.com\"' '    zonefile: \"example.com.zone\"' > $f"],
      ["/bin/sh", "-c", "f=/var/db/nsd/zones/example.com.zone; [ -e $f ] || printf '%s\\n' '$ORIGIN example.com.' '$TTL 3600' '@    IN SOA ns1.example.com. hostmaster.example.com. ( 2026103001 3600 900 1209600 300 )' '@    IN NS  ns1.example.com.' 'ns1  IN A   192.0.2.53' 'www  IN A   192.0.2.80' > $f"],
      ["/usr/sbin/chown", "-R", "nsd:nsd", "/var/db/nsd", "/var/run/nsd"],
      ["/usr/local/sbin/nsd-checkconf", "/usr/local/etc/nsd/nsd.conf"],
      ["/usr/local/sbin/nsd-checkzone", "example.com", "/var/db/nsd/zones/example.com.zone"],
    ],
    health: { tcp: 53, wait_seconds: 30 },
    resources: { memory: "256M", disk: "2G", cpu: "1" },
    notes: "The server answers for example.com from /var/db/nsd/zones/example.com.zone.\nPut your zone files there, name each in a zone: block of\n/usr/local/etc/nsd/nsd.conf, run nsd-checkconf /usr/local/etc/nsd/nsd.conf\nand service nsd restart. Raise the SOA serial with every change.\n\nPrimary (this jail 192.0.2.53, the secondary 198.51.100.53), in the zone:\nblock:\n  notify: 198.51.100.53 NOKEY\n  provide-xfr: 198.51.100.53 NOKEY\n\nSecondary (the primary 192.0.2.53), in the zone: block, after deleting the\nstarter zone file (the transfer writes it):\n  allow-notify: 192.0.2.53 NOKEY\n  request-xfr: 192.0.2.53 NOKEY\n\nUse a TSIG key instead of NOKEY across untrusted networks: a key: block\nwith name, algorithm hmac-sha256 and secret, the same on both sides, and its\nname in place of NOKEY. Delegate the zone at its parent to both servers.\n",
  },
  {
    version: 1, name: "mail", title: "Mail (Postfix and Dovecot)", summary: "A starting point for a single-domain mail server, SMTP with Postfix and IMAP with Dovecot.",
    description: "Postfix receives mail for one domain on port 25 and takes mail from your\nusers on the submission port 587; Dovecot serves the mailboxes over IMAP.\nMail users are system users of the jail with their homes under /home/mail,\nand mail is delivered to Maildir/ in each home.\n\nThis is a starting point: the domain is example.com until you change it,\nthere is no TLS until you add a certificate (so clients cannot log in from\nother machines yet), and there is no spam filter, no DKIM signing and no\nwebmail. The notes list the next steps and the DNS records.\n",
    category: "communication", homepage: "https://www.postfix.org/", license: "EPL-2.0 OR IPL-1.0 (Postfix), MIT and LGPL-2.1 (Dovecot)", icon: "mail.svg", image: IMAGE,
    packages: [{ name: "postfix", repo: "ports", version: "3.10" }, { name: "dovecot", repo: "ports", version: "2.3" }],
    services: [
      { name: "postfix", rc: {"sendmail_enable": "NONE"}, start: true },
      { name: "dovecot", start: true },
    ],
    ports: [
      { name: "smtp", port: 25, proto: "tcp", description: "Mail from other servers to your domain.", expose: true },
      { name: "submission", port: 587, proto: "tcp", description: "Mail from your users; needs TLS and a login, so not usable until a certificate is set.", expose: true },
      { name: "imap", port: 143, proto: "tcp", description: "IMAP; logins are refused without TLS except from the jail itself.", expose: true },
      { name: "imaps", port: 993, proto: "tcp", description: "IMAP over TLS; not listening until a certificate is configured.", expose: false },
    ],
    data: [
      { path: "/home/mail", description: "The mail users' homes and their Maildir mailboxes." },
      { path: "/var/spool/postfix", description: "The Postfix queue." },
    ],
    config: [
      { path: "/usr/local/etc/postfix/main.cf", description: "Postfix settings (domain, TLS); 'postfix reload' applies a change.", restart: "postfix" },
      { path: "/usr/local/etc/postfix/master.cf", description: "The Postfix services, including submission on 587.", restart: "postfix" },
      { path: "/usr/local/etc/dovecot/dovecot.conf", description: "Dovecot settings (written at the installation for Dovecot 2.3).", restart: "dovecot" },
    ],
    logs: [{ name: "maillog", path: "/var/log/maillog", description: "Both servers log to syslog, facility mail." }],
    setup: [
      ["/bin/sh", "-c", "cd /usr/local/etc/postfix && for f in main.cf master.cf; do [ -e $f ] || cp $f.sample $f; done"],
      ["/usr/local/sbin/postconf", "-e", "mydomain = example.com", "myhostname = mail.example.com", "myorigin = $mydomain", "mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain", "inet_interfaces = all", "home_mailbox = Maildir/", "alias_maps = $default_database_type:/etc/mail/aliases", "alias_database = $default_database_type:/etc/mail/aliases", "smtpd_sasl_type = dovecot", "smtpd_sasl_path = private/auth"],
      ["/usr/local/sbin/postconf", "-M", "submission/inet=submission inet n - n - - smtpd"],
      ["/usr/local/sbin/postconf", "-P", "submission/inet/syslog_name=postfix/submission", "submission/inet/smtpd_tls_security_level=encrypt", "submission/inet/smtpd_sasl_auth_enable=yes", "submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"],
      ["/usr/local/sbin/postfix", "check"],
      ["/usr/local/sbin/postfix", "set-permissions"],
      ["/usr/local/sbin/postalias", "/etc/mail/aliases"],
      ["/bin/mkdir", "-p", "/usr/local/etc/mail"],
      ["/bin/sh", "-c", "printf '%s\\t%s\\n' sendmail /usr/local/sbin/sendmail send-mail /usr/local/sbin/sendmail mailq /usr/local/sbin/sendmail newaliases /usr/local/sbin/sendmail > /usr/local/etc/mail/mailer.conf"],
      ["/bin/sh", "-c", "f=/usr/local/etc/dovecot/dovecot.conf; [ -e $f ] || printf '%s\\n' '# Starter configuration of the mail app (Dovecot 2.3); see its notes.' 'protocols = imap' 'ssl = no' 'disable_plaintext_auth = no' 'mail_location = maildir:~/Maildir' 'passdb {' '  driver = pam' '}' 'userdb {' '  driver = passwd' '}' 'service auth {' '  unix_listener /var/spool/postfix/private/auth {' '    mode = 0660' '    user = postfix' '    group = postfix' '  }' '}' 'service imap-login {' '  inet_listener imaps {' '    port = 0' '  }' '}' > $f"],
      ["/usr/local/bin/doveconf", "-n"],
    ],
    health: { tcp: 25, wait_seconds: 60 },
    resources: { memory: "512M", disk: "20G", cpu: "1" },
    notes: "A starting point: example.com, no TLS. In the jail (jailops shell NAME):\n- Domain: postconf -e 'mydomain = YOUR.DOMAIN' 'myhostname = mail.YOUR.DOMAIN',\n  then postfix reload.\n- A user: pw useradd -n alice -d /home/mail/alice -m -s /usr/sbin/nologin,\n  then passwd alice. Mail to alice@YOUR.DOMAIN lands in ~alice/Maildir.\n- TLS: put a certificate and key in the jail, then postconf -e\n  'smtpd_tls_cert_file = CERT' 'smtpd_tls_key_file = KEY'\n  'smtpd_tls_security_level = may' and postfix reload; in dovecot.conf set\n  ssl = required, ssl_cert = <CERT, ssl_key = <KEY,\n  delete the port = 0 line of the imaps listener and service dovecot restart. Then clients use 587 and 993 with a login.\nDNS for YOUR.DOMAIN (the jail's public address must be reachable on 25):\n- A/AAAA: mail.YOUR.DOMAIN -> the address; PTR of the address back to\n  mail.YOUR.DOMAIN (set by whoever owns the address).\n- MX: YOUR.DOMAIN -> 10 mail.YOUR.DOMAIN\n- SPF: TXT on YOUR.DOMAIN \"v=spf1 mx -all\"\n- DKIM: needs a signing service, which this app does not include; without\n  it, large providers may file your mail as spam.\n- DMARC: TXT on _dmarc.YOUR.DOMAIN \"v=DMARC1; p=none; rua=mailto:postmaster@YOUR.DOMAIN\"\nMany networks block outgoing port 25; check before relying on it.\n",
  },
  {
    version: 1, name: 'memcached', title: 'memcached', summary: 'Distributed in-memory object cache; a local example definition.',
    description: 'memcached keeps objects in memory for the applications that ask it, to spare a database\nthe same queries. This definition is the worked example of docs/apps.md ("Write your own\napp"): it lives in the host\'s own directory, apps.local_dir.\n',
    category: 'database', homepage: 'https://memcached.org/', license: 'BSD-3-Clause', image: IMAGE,
    packages: [{ name: 'memcached', repo: 'ports', version: '1.6.39' }],
    services: [{ name: 'memcached', rc: { memcached_flags: '-l 0.0.0.0 -m 64' }, start: true }],
    ports: [{ name: 'memcached', port: 11211, proto: 'tcp', description: 'The memcached protocol; no authentication, keep it on the jail network.', expose: false }],
    data: [],
    config: [],
    logs: [],
    setup: [['/bin/mkdir', '-p', '/var/run/memcached'], ['/usr/sbin/chown', 'nobody:nobody', '/var/run/memcached']],
    health: { tcp: 11211, wait_seconds: 30 },
    resources: { memory: '128M', disk: '1G', cpu: '1' },
    notes: 'The cache is empty after every start. Point the applications at <address>:11211;\nanyone on the jail network can read and write it.\n',
  },
]

/** The definitions read from the host's own directory (apps.local_dir) instead of the packaged catalog. */
const LOCAL = new Set(['memcached'])
const sourceOf = (name: string) => (LOCAL.has(name) ? 'local' : 'catalog') as AppSummary['source']
const fileOf = (name: string) => `${LOCAL.has(name) ? '/usr/local/etc/jailops/apps' : '/usr/local/share/jailops/apps'}/${name}.yaml`

/** An operator's own definition that fails validation: listed with the reason, never installable. */
const broken: AppSummary = {
  name: 'wiki', title: 'Team wiki', summary: 'A definition dropped into the catalog directory by hand.', category: 'tools', valid: false, source: 'catalog',
  error: 'wiki.yaml: data[0].path "/etc/wiki" lies under the base system; data paths lie below /var, /usr/local or /home',
}

export function catalog(): AppSummary[] {
  return [
    ...definitions.map((a) => ({ name: a.name, title: a.title, summary: a.summary, category: a.category, version: a.packages[0]?.version, valid: true, source: sourceOf(a.name) })),
    broken,
  ]
}

export function detail(name: string): AppDetail | 'invalid' | undefined {
  if (name === broken.name) return 'invalid'
  const a = definitions.find((x) => x.name === name)
  if (!a) return undefined
  return { definition: structuredClone(a), hash: hash(a.name), file: fileOf(a.name), source: sourceOf(a.name), ...(ICONS[a.name] ? { icon: ICONS[a.name] } : {}) }
}
export const appHash = hash
export const LABEL = 'jailops.app'
export const invalidApp = broken

/** The steps the server describes for an installation, in its "NN name: effect" form. */
export function installSteps(a: App, jail: string, project: string, image: string): string[] {
  const root = `/jailops/${project}/${jail}/root`
  const out: Array<[string, string]> = [
    ['create-jail', `create thin jail ${jail} from ${image} with ${a.data?.length ?? 0} data volume(s) and the labels jailops.app, jailops.app.hash`],
    ['start-jail', `start ${jail}`],
    // one step per repository, the FreeBSD one first, as the server does
    ...(['ports', 'jailops'] as const).flatMap((repo): Array<[string, string]> => {
      const names = a.packages.filter((p) => (p.repo ?? 'ports') === repo).map((p) => p.name)
      return names.length ? [[`install-packages-${repo}`, `pkg -r ${root} install -y ${repo === 'jailops' ? '-r jailops ' : ''}${names.join(' ')}`]] : []
    }),
    ['refresh-library-cache', 'in the jail: /sbin/ldconfig -m /usr/local/lib'],
    ['record-version', `pkg -r ${root} query %v ${a.packages[0].name}, then label jailops.app.version`],
    ['write-rc-conf', `set ${(a.services ?? []).flatMap((s) => [`${s.name}_enable`, ...Object.keys(s.rc ?? {})]).join(', ')} in ${root}/etc/rc.conf`],
    ...(a.setup ?? []).map((cmd, i): [string, string] => [`setup-${i + 1}`, `in the jail: ${cmd.join(' ')}`]),
    ...(a.services ?? []).filter((s) => s.start !== false).map((s): [string, string] => [`start-service-${s.name}`, `in the jail: /usr/sbin/service ${s.name} start`]),
  ]
  const h = a.health
  if (h) out.push(['health-check', h.http ? `GET http://<first address>:${h.http.port}${h.http.path} until it answers ${h.http.status ?? 200}, at most ${h.wait_seconds ?? 60} attempts` : h.tcp ? `connect to <first address>:${h.tcp} until it accepts, at most ${h.wait_seconds ?? 60} attempts` : `in the jail: ${h.exec?.join(' ')} until it exits 0, at most ${h.wait_seconds ?? 60} attempts`])
  out.push(['close-firewall', `firewall policy app-${jail} (managed by app access): deny every inbound connection until jailops app allow ${jail} --from SOURCE`])
  out.push(['snapshot', `snapshot every dataset of ${jail} as app-installed`])
  out.push(['enable-autostart', `boot.autostart of ${jail}: start with the host`])
  return out.map(([n, d], i) => `${String(i + 1).padStart(2, '0')} ${n}: ${d}`)
}

// ---- jail logs ---------------------------------------------------------------------------------------

interface Line { text: string; ts: number }
/** A read of the demo with the time each line was written. */
export type DemoRead = Omit<JailLogRead, 'lines'> & { entries: Array<{ text: string; ts: number; n?: number }> }
interface File { lines: Line[]; size: number; grows: boolean; last: number; rotations: number; next: () => string }

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const two = (n: number) => String(n).padStart(2, '0')
const sys = (t: number) => { const d = new Date(t); return `${MON[d.getMonth()]} ${String(d.getDate()).padStart(2, ' ')} ${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}` }
const web = (t: number) => { const d = new Date(t); return `${two(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} +0000` }

const CLIENTS = ['192.0.2.41', '198.51.100.23', '203.0.113.9', '10.20.0.12', '2001:db8:20:1::77']
const PAGES: Array<[string, number, number]> = [['/', 200, 615], ['/index.html', 200, 615], ['/assets/app.css', 200, 18342], ['/assets/app.js', 200, 90211], ['/favicon.ico', 404, 153], ['/api/health', 200, 2], ['/login', 302, 0], ['/robots.txt', 200, 26], ['/.env', 404, 153]]
const AGENTS = ['Mozilla/5.0 (X11; FreeBSD amd64; rv:140.0) Gecko/20100101 Firefox/140.0', 'curl/8.16.0', 'Prometheus/3.15.0', 'Mozilla/5.0 (compatible; ExampleBot/2.1)']

function pick<T>(xs: T[], i: number): T { return xs[i % xs.length] }

function generator(kind: string, jail: string): (t: number, i: number) => string {
  const host = jail
  switch (kind) {
    case 'access':
      return (t, i) => { const [p, st, sz] = pick(PAGES, i * 7 + 3); return `${pick(CLIENTS, i * 3 + 1)} - - [${web(t)}] "GET ${p} HTTP/1.1" ${st} ${sz} "-" "${pick(AGENTS, i)}"` }
    case 'error':
      return (t, i) => { const d = new Date(t); return `${d.getFullYear()}/${two(d.getMonth() + 1)}/${two(d.getDate())} ${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())} [${i % 5 ? 'error' : 'warn'}] 4812#100231: *${900 + i} open() "/usr/local/www/nginx/${i % 2 ? 'favicon.ico' : '.env'}" failed (2: No such file or directory), client: ${pick(CLIENTS, i)}, server: localhost` }
    case 'auth':
      return (t, i) => `${sys(t)} ${host} sshd[${3100 + i}]: ${i % 3 ? `Accepted publickey for deploy from 203.0.113.5 port ${51000 + i} ssh2: ED25519 SHA256:q2Vd7nXbH1` : `Invalid user admin from 198.51.100.66 port ${40000 + i}`}`
    case 'cron':
      return (t, i) => `${sys(t)} ${host} /usr/sbin/cron[${5000 + i}]: (root) CMD (/usr/libexec/atrun)`
    case 'daemon':
      // One line carries terminal escape sequences, as a careless service would print them: the viewer must show them inert.
      return (t, i) => i % 9 === 4 ? `${sys(t)} ${host} prometheus[2231]: \x1b[31mlevel=WARN\x1b[0m msg="Error on ingesting samples" err="out of order sample"\x07` : `${sys(t)} ${host} prometheus[2231]: time=${new Date(t).toISOString()} level=INFO source=head.go msg="Head GC completed" duration=${(1.2 + (i % 7) * 0.4).toFixed(1)}ms`
    case 'pg':
      // ISO timestamps, and a DETAIL line now and then that has none of its own (it belongs to the line before).
      return (t, i) => i % 6 === 5 ? `\tDETAIL:  Key (id)=(${4100 + i}) already exists.` : `${new Date(t).toISOString()} [${2400 + (i % 5)}] ${i % 6 === 4 ? 'ERROR:  duplicate key value violates unique constraint "orders_pkey"' : `LOG:  checkpoint complete: wrote ${12 + (i % 40)} buffers`}`
    case 'valkey':
      return (t, i) => `2231:M ${new Date(t).getDate()} ${MON[new Date(t).getMonth()]} ${new Date(t).getFullYear()} ${new Date(t).toTimeString().slice(0, 8)}.${String(i % 1000).padStart(3, '0')} * ${i % 4 ? '100 changes in 300 seconds. Saving...' : 'Background saving terminated with success'}`
    default:
      return (t, i) => {
        const m = [
          `kernel: pflog0: promiscuous mode enabled`,
          `syslogd: kernel boot file is /boot/kernel/kernel`,
          `postgres[${2400 + (i % 5)}]: [${(i % 3) + 1}-1] LOG:  checkpoint complete: wrote ${12 + (i % 40)} buffers (0.1%); write=${(0.4 + (i % 9) / 10).toFixed(1)} s`,
          `nginx: the configuration file /usr/local/etc/nginx/nginx.conf syntax is ok`,
          `ntpd[${880}]: leap second file expires soon`,
          `postgres[${2410 + (i % 3)}]: [1-1] LOG:  connection received: host=10.20.0.11 port=${52000 + i}`,
          `su[${7100 + i}]: deploy to root on /dev/pts/0`,
        ]
        return `${sys(t)} ${host} ${pick(m, i)}`
      }
  }
}

/** The files below /var/log of a demo jail, by what it runs. */
interface Layout { name: string; kind: string; count: number; grows: boolean; rotated?: number; gz?: number }
function layout(jail: string, app: string): Layout[] {
  const base: Layout[] = [
    { name: 'messages', kind: 'messages', count: 260, grows: true, rotated: 1, gz: 2 },
    { name: 'auth.log', kind: 'auth', count: 60, grows: false, gz: 1 },
    { name: 'cron', kind: 'cron', count: 120, grows: false },
    { name: 'daemon.log', kind: 'daemon', count: 90, grows: app === 'prometheus' || app === 'forgejo' },
  ]
  if (app === 'nginx' || jail === 'web' || jail === 'proxy') base.push({ name: 'nginx/access.log', kind: 'access', count: 400, grows: true, rotated: 1 }, { name: 'nginx/error.log', kind: 'error', count: 40, grows: false })
  if (app === 'valkey') base.push({ name: 'valkey/valkey.log', kind: 'valkey', count: 80, grows: true })
  if (app === 'postgresql') base.push({ name: 'postgresql/postgresql.log', kind: 'pg', count: 80, grows: true })
  if (app === 'forgejo') base.push({ name: 'forgejo/forgejo.log', kind: 'messages', count: 50, grows: true })
  return base
}

/** Log state of every jail of the demo, created on first use. */
export function demoLogs() {
  const jails = new Map<string, Map<string, File & { modified: number }>>()

  function filesOf(jail: string, app: string) {
    let m = jails.get(jail)
    if (m) return m
    m = new Map()
    const now = Date.now()
    for (const f of layout(jail, app)) {
      const gen = generator(f.kind, jail)
      const mk = (count: number, endAgo: number, step: number, seed: number) => {
        const lines: Line[] = []
        for (let i = 0; i < count; i++) { const ts = now - endAgo - (count - i) * step; lines.push({ text: gen(ts, seed + i), ts }) }
        return lines
      }
      let i = f.count
      const step = Math.round((26 * 3600_000) / f.count) // a day and a bit, so "since" has something to cut
      const lines = mk(f.count, 4_000, step, 0)
      const file = { lines, size: 0, grows: f.grows, last: now, rotations: 0, modified: now - 4_000, next: () => gen(Date.now(), i++) }
      file.size = lines.reduce((n, l) => n + l.text.length + 1, 0)
      m.set(f.name, file)
      for (let r = 0; r < (f.rotated ?? 0); r++) {
        const old = mk(f.count, 86400_000 * (r + 1), step, 5000 + r * 1000)
        m.set(`${f.name}.${r}`, { lines: old, size: old.reduce((n, l) => n + l.text.length + 1, 0), grows: false, last: now, rotations: 0, modified: now - 86400_000 * (r + 1), next: () => '' })
      }
      for (let r = 0; r < (f.gz ?? 0); r++) {
        const at = (f.rotated ?? 0) + r
        m.set(`${f.name}.${at}.gz`, { lines: [], size: 18_000 + r * 2311, grows: false, last: now, rotations: 0, modified: now - 86400_000 * (at + 1), next: () => '' })
      }
    }
    jails.set(jail, m)
    return m
  }

  /** A file that grows gets about one line a second while someone reads it; a long one is rotated now and then. */
  function grow(f: File & { modified: number }): void {
    if (!f.grows) return
    const now = Date.now()
    const n = Math.min(5, Math.floor((now - f.last) / 900))
    if (n < 1) return
    f.last = now
    if (f.lines.length > 1200) {
      f.lines = []
      f.size = 0
      f.rotations++
    }
    for (let i = 0; i < n; i++) {
      const text = f.next()
      f.lines.push({ text, ts: now })
      f.size += text.length + 1
    }
    f.modified = now
  }

  return {
    list(jail: string, app: string): JailLogFile[] {
      return [...filesOf(jail, app).entries()].map(([name, f]) => {
        const compressed = /\.(gz|bz2|xz)$/.test(name)
        return { name, size: f.size, modified_at: new Date(f.modified).toISOString(), kind: compressed || /\.\d+$/.test(name) ? 'rotated' : 'active', ...(compressed ? { compressed: true } : {}) }
      })
    },
    read(jail: string, app: string, file: string, q: URLSearchParams): JailLogRead | 'missing' | 'compressed' {
      const r = this.entries(jail, app, file, q)
      if (typeof r === 'string') return r
      const { entries, ...out } = r
      return { ...out, lines: entries.map((l) => ({ text: l.text, ...(l.n ? { n: l.n } : {}) })) }
    },
    /** A read as the server makes it, with the time each line was written (the unified view merges by it). */
    entries(jail: string, app: string, file: string, q: URLSearchParams): DemoRead | 'missing' | 'compressed' {
      const f = filesOf(jail, app).get(file)
      if (!f) return 'missing'
      if (/\.(gz|bz2|xz)$/.test(file)) return 'compressed'
      let offset = Number(q.get('offset') ?? 0)
      if (offset > 0) grow(f)
      const out: DemoRead = { jail, file, entries: [], next_offset: f.size }
      if (offset > f.size) { out.rotated = true; offset = 0 }
      const sinceRaw = q.get('since') ?? ''
      const m = /^(\d+)([mhd])$/.exec(sinceRaw)
      const since = m ? Date.now() - Number(m[1]) * { m: 60_000, h: 3600_000, d: 86400_000 }[m[2] as 'm' | 'h' | 'd'] : 0
      const grep = (q.get('grep') ?? '').toLowerCase()
      const tail = Number(q.get('tail') ?? 200)
      let pos = 0
      f.lines.forEach((l, i) => {
        const start = pos
        pos += l.text.length + 1
        if (start < offset) return
        if (since && l.ts < since) return
        if (grep && !l.text.toLowerCase().includes(grep)) return
        out.entries.push({ text: l.text, ts: l.ts, ...(offset === 0 ? { n: i + 1 } : {}) })
      })
      if (out.entries.length > tail) { out.entries = out.entries.slice(-tail); out.truncated = true }
      return out
    },
  }
}
