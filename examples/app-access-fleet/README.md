# Apps and who may reach them

PostgreSQL and nginx installed from the application catalog, each as its own jail of the project `shop`, and the grants
that open them: the web jail may reach the database (with a role and a database `shop` made in PostgreSQL), and a
documentation network may reach the web server on port 80. Everything else stays closed: an installed app accepts
nothing until it is allowed.

    jailops-sync -C examples/app-access-fleet validate
    jailops-sync -C examples/app-access-fleet plan
    jailops-sync -C examples/app-access-fleet sync --apply

`sync --apply` installs the two apps, then allows the sources. The connection string of the new role `shop`
(`postgres://shop:<password>@<db address>:5432/shop?sslmode=disable`) is printed **once**, in the output of that
apply, and nowhere else: not in the apply log, not in the repository. Put it where the web application reads it. A
second apply changes nothing and never makes a new password; `jailops app allow db --from jail:web --rotate` does.

See [../../docs/fleet-sync.md](../../docs/fleet-sync.md) ("Apps and who may reach them").
