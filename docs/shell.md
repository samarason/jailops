# The shell of a jail, and its prompt

A new FreeBSD jail comes with **bash** and a coloured prompt that says where you are: the jail, its project and the host it
runs on, so a shell inside a jail is recognisable at a glance:

    root@web [shop/babel]:/#           root@web light blue (256-colour number 39), "[shop/babel]" grey (245)

`jailops shell web` and the console's Console tab start bash; every interactive bash in the jail (root, users you add,
`su`, ssh logins) shows the prompt. Nothing has to be edited by hand for the common cases, and everything can be
changed or removed.

## What a new jail gets

When the request (and the jail's profiles) do not say otherwise, the daemon fills two keys of a new FreeBSD jail from
`jailopsd.yaml`, so `jailops config show NAME` shows what it got:

| Key | Default | Meaning |
|---|---|---|
| `shell` | `/usr/local/bin/bash` | the shell of `jailops shell` and the console: `bash`, `sh` or a path inside the jail |
| `prompt` | `default` | the bash prompt of every user: `default`, `short`, `none`, or a PS1 text |

At the jail's **first start** JailOps installs the `bash` package into the jail from the host (`pkg -r ROOT install -y
bash`, before anything runs in the jail, with the host's own network, whatever the jail's firewall says) and writes the prompt.
If the host cannot fetch it, the setup after the start tries once more from inside the jail (`pkg -j JAIL install -y bash`, over
the jail's own network); the start never waits for it longer than a minute, and `jailops shell` of a jail that still has no bash says
which command fixes it (`jailops jail shell-setup NAME`) and that `jailops set NAME shell sh` uses FreeBSD's own shell instead. Both live below `/usr/local`, a persistent
dataset of a thin jail, so they survive an OS update (the root swap of `jailops jail upgrade` and of the nightly image
upgrade); a thick jail is upgraded in place. App installations do the same right after the app's packages.

If the host cannot reach its package repository, the start still succeeds: the jail shows a `ShellSetup` condition
(`jailops jail show NAME`, and a notice on the jail's page in the console), `jailops shell` says how to repair it, and
`jailops jail shell-setup NAME` tries again. It is not retried at every start.

Linux jails are left alone: they keep the shell and prompt of their distribution, and the prompt key is refused for them.

## The files

| File | Owner | What it does |
|---|---|---|
| `/usr/local/etc/profile.d/jailops-env.sh` | JailOps, the same text in every jail | exports `JAILOPS_JAIL`, `JAILOPS_PROJECT` and `JAILOPS_HOST` from the jail's `env` parameters |
| `/usr/local/etc/profile.d/jailops-prompt.sh` | JailOps, rewritten from the `prompt` key | sets `PS1` in an interactive bash, nothing else |
| `/usr/local/etc/bash.bashrc` | you; JailOps keeps a marked block at its top | read by every interactive bash that is not a login shell |
| `/usr/local/etc/profile` | you; JailOps keeps a marked block at its top | read by every login bash (and by `sh -l` through `/etc/profile`) |

The FreeBSD `bash` package installs neither start-up file; it is built with its `SYSBASHRC` option, so bash reads
`/usr/local/etc/bash.bashrc` and `/usr/local/etc/profile` (not `/etc/profile`). The marked block sources the variables
first and then the prompt:

    # BEGIN jailops shell: managed by JailOps (jailops config set JAIL prompt none keeps the variables and drops the prompt)
    if [ -r /usr/local/etc/profile.d/jailops-env.sh ]; then . /usr/local/etc/profile.d/jailops-env.sh; fi
    if [ -r /usr/local/etc/profile.d/jailops-prompt.sh ]; then . /usr/local/etc/profile.d/jailops-prompt.sh; fi
    # END jailops shell

With `prompt: none` the prompt file and its line are gone and the variables script stays: the variables are useful without a prompt.

Everything else in those two files is yours and stays as it is. The block is at the top, so your own lines come after it
and win. A block you cut in half by hand is refused (the operation names the file), never guessed at.

The prompt file sets `PS1` only when bash runs interactively (`PS1` is set): scripts, `bash -c` and `bash -lc` are not
affected, and `sh` ignores it (it keeps FreeBSD's own prompt from `/root/.shrc`).

## Where the jail is

The default prompt is `user@jail`, then, in a quiet grey, the **project** and the **host** the jail runs on in square
brackets, then the directory and `#` (root) or `$`:

    root@web [shop/babel]:/usr/local/etc#      a root shell, an ssh login or `jailops shell`
    ann@web [shop/babel]:~$                    a user

`user@jail` is in the colour of `jails.prompt_color` (39, light blue, unless you change it); the tag is grey (245) and
the directory has no colour. The jail's host name is not changed: `\h` is the jail's host name, which is the jail's
name. If the project or the host is not known the tag is `[shop]` or `[babel]`, and without both there is no tag.
The `short` prompt has no tag: `root@web:/usr/local/etc#`.

The tag is not written into the prompt file. Every interactive bash of the jail has three variables, and the prompt
reads them each time it is shown:

| Variable | Is |
|---|---|
| `JAILOPS_JAIL` | the name of the jail |
| `JAILOPS_PROJECT` | the project of the jail |
| `JAILOPS_HOST` | the short name of the host: the first label of its host name, in lower case (`Babel.example.org` is `babel`) |

**Where they come from.** Every start renders three parameters into the jail's `jail.conf`, on the host the jail is
started on: `env.jailops_jail`, `env.jailops_project` and `env.jailops_host` (a value that is not known has no
parameter; the values hold only lower-case letters, digits and hyphens). FreeBSD gives a jail its `env` parameters as the
read-only sysctl `security.jail.env`, lines of `key=value`, which the jail cannot change:

    jls -j web env                       # on the host
    sysctl -n security.jail.env          # in any shell inside the jail
    jailops_jail=web
    jailops_project=shop
    jailops_host=babel

`jailops-env.sh` reads that sysctl once when a bash starts and exports the three variables. It uses only these three
keys and only values of the kind above, so another tool that writes the same buffer cannot set anything else. The
variables are right after a rename (a jail is renamed while it is stopped, and the next start renders the new name) and
after a jail has moved to another host, and nothing in the jail's files changes for either. A shell that is already open
keeps its values until the next login. `sh`, scripts, `bash -c` and `ssh host command` do not read the script and do not
have the variables; they can read the sysctl.

A prompt text of your own may use three words in braces, which become references to the variables:

| Word | Reads |
|---|---|
| `{jail}` | `JAILOPS_JAIL` |
| `{project}` | `JAILOPS_PROJECT` |
| `{host}` | `JAILOPS_HOST` |

A variable that is not known is empty, and the text around it stays as you wrote it. Any other `{` or `}` is refused, and
the message names the three words.

    jailops config set web prompt '\u@{jail} [{project}/{host}]:\w\$ '      one jail:  root@web [shop/babel]:/#
    jailops config set web prompt short                                       no tag:    root@web:/#
    jailops config set web prompt none                                        no prompt: the variables stay

In your own `~/.bashrc` the variables are ordinary variables, so a prompt of your own can use them in any way:

    PS1='\[\e[38;5;39m\]\u@\h\[\e[0m\] ${JAILOPS_HOST-}/${JAILOPS_PROJECT-}:\w\$ '

If you write a prompt yourself: wrap every colour sequence, including the final reset, in `\[` and `\]` so bash measures
the line correctly, and end it with a space so what you type does not touch it.

The colour says one thing: the kind of host. Set `prompt_color` once per host, in `jailopsd.yaml`, red for production and
green for test, and the same text tells hosts apart at a glance. For **every new jail of a host**:

```yaml
jails:
  prompt: default      # default, short, none, or a PS1 text
  prompt_color: 196    # user@jail in red on a production host
```

## Overriding it

**For one user:** set `PS1` in your own start-up file. Bash reads the system files first, so yours wins:

- `~/.bashrc` for the shells `jailops shell` and the console open (interactive, not login shells);
- `~/.bash_profile` (or `~/.profile`) for login shells such as ssh logins. The usual way to have one place for both is a
  `~/.bash_profile` with `. ~/.profile` and `. ~/.bashrc` in it.

**For one jail:**

    jailops config set web prompt '\[\e[38;5;196m\]\u@\h:\w\$\[\e[0m\] '   # red, with a space after # or $
    jailops config set web prompt none       # remove the prompt file; the variables stay
    jailops config set web prompt short      # user@jail:dir without the grey tag
    jailops config set web prompt default    # back to the default
    jailops set web shell sh                 # jailops shell and the console start /bin/sh again

A running jail gets a new prompt at once, a stopped one at its next start. The console's Configuration tab has both keys.
To drop bash itself, set the shell to `sh` and remove the package by hand (`pkg delete bash`
in the jail if it has `pkg`); JailOps does not install it again on its own.

**For all new jails of a host** (`/usr/local/etc/jailops/jailopsd.yaml`, read at the daemon's start):

```yaml
jails:
  shell: bash          # or sh: nothing is installed, and the prompt key stays empty
  prompt: default      # default, short, none, or a PS1 text
  prompt_color: 39     # 256-colour number of user@jail (39 light blue, 40 green, 196 red)
```

A jail whose prompt is `default` takes a changed `prompt_color` at its next start; a jail with a PS1 text of its own
keeps it.

`jailops create web --shell sh` or `--prompt none` (and `shell`/`prompt` in a file for `jailops apply` or `jailops-sync`)
choose per jail at creation; a profile may set both keys too.

## Existing jails

A jail whose `shell` and `prompt` keys are empty is left alone: nothing changes on its own, not at a start and not at an
upgrade. Ask for it:

    jailops jail shell-setup web

It fills the keys the jail does not set from the host's defaults, installs bash when it is the shell and missing, and
writes the prompt; it prints the `PS1` it wrote and what it did. Running it again repairs the files and installs
nothing. The jail must run. In the console, a jail whose shell is bash but has no bash offers the same on its Console
tab (**Install bash and the prompt**).

## What a prompt may contain

The prompt is written into a file that bash reads as shell code, and bash expands variables and commands in `PS1` each
time it shows the prompt. JailOps therefore accepts an allow-list only (`api.CheckPrompt`, used by the API, the CLI and
`jailopsd.yaml`):

- at most 256 bytes of printable UTF-8 on one line;
- a `{` only as the start of `{jail}`, `{project}` or `{host}` and a `}` only as the end of one (see [Where the jail is](#where-the-jail-is)), or inside `\D{...}`;
- no `'` and no `` ` ``; a `$` only as the escape `\$` (`#` for root, `$` for everyone else);
- a backslash only before one of bash's prompt escapes: `\u \h \H \w \W \$ \# \! \j \l \s \t \T \@ \A \d \D{...} \n \r
  \a \e \[ \]` and the octal escapes `\033` (escape) and `\007` (bell); colours are `\[\e[...m\]`;
- refused, because bash would turn them into a character it then expands: `\\` (a backslash), and every other octal
  escape (`\044` is a `$`, `\140` a backquote).
The accepted text is then written as one single-quoted assignment, `PS1='...'`. A prompt that runs a command (a git
branch, the exit status) belongs in your own `~/.bashrc`.

## The environment of jailops shell

`jailops shell` and the console run the shell through `jexec` without a login: bash starts as an interactive shell that
is not a login shell (it reads `bash.bashrc` and `~/.bashrc`), in `/`, as root. The session gets
`PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin` (the path of a login, so what packages install is
found) and `HOME=/root`; the jail's own `env.*` keys and what the caller sends come after and win. From a terminal,
`jailops shell` and `jailops exec -t` pass the terminal's `TERM`, so bash edits lines as it does in a login (without it,
bash assumes a dumb terminal). The console's terminal understands a small part of what a terminal does and sends no
`TERM`; bash then works line by line, and the coloured prompt shows (the console draws the 256 colours).

The login shell of root in `/etc/passwd` is not changed: `su -` and a console login keep `/bin/sh`. Change it in the jail
with `chsh -s /usr/local/bin/bash` if you want bash there too.

## The host

The green prompt on the host is the same mechanism, written once by hand (JailOps never edits the host's shell files):

    pkg install bash
    mkdir -p /usr/local/etc/profile.d
    printf '%s\n' 'if [ -n "${BASH_VERSION-}" ] && [ -n "${PS1-}" ]; then' \
      "    PS1='\\[\\e[38;5;40m\\]\\u@\\h:\\w\\\$\\[\\e[0m\\] '" 'fi' > /usr/local/etc/profile.d/host-prompt.sh
    for f in /usr/local/etc/profile /usr/local/etc/bash.bashrc; do
      printf '%s\n' '. /usr/local/etc/profile.d/host-prompt.sh' >> "$f"
    done

`chsh -s /usr/local/bin/bash` makes bash your login shell. Your own `~/.bashrc` wins here as in a jail.
[appliance.md](appliance.md#the-shell-prompt-of-the-host) says why this is not a host management module.
