# CI supply chain

What the workflows in `.github/workflows` run that is not ours, and how to pin it. The workflows name actions by a
tag (`@v7`), which the action's owner can move to other code at any time; a full commit SHA cannot move.

## What runs, with what rights

| Workflow | Permissions of `GITHUB_TOKEN` | Actions |
|---|---|---|
| `ci.yml` (every push and pull request) | `contents: read` for every job | `actions/checkout`, `actions/setup-go`, `actions/setup-node`, `actions/cache`, `actions/upload-artifact`, `actions/download-artifact`, **`vmactions/freebsd-vm`** |
| `release.yml` (a tag `v*`) | `contents: write` (it publishes the release) | `actions/checkout`, `actions/setup-go`, `actions/setup-node`, **`goreleaser/goreleaser-action`** |

The two in bold come from third parties: `vmactions/freebsd-vm` runs the FreeBSD VM that builds and tests the tree, and
`goreleaser/goreleaser-action` runs with the token that can write the release. They matter most; the `actions/*` ones
are GitHub's own and should be pinned the same way.

The web-e2e job rewrites the runner's apt mirror list as root; every mirror in it is an `https` URL, and apt checks the
signed package indexes whatever the transport.

## Pinning an action to a commit

Run, with the GitHub CLI signed in, for each action and the tag the workflow uses now:

    gh api repos/vmactions/freebsd-vm/commits/v1 --jq .sha
    gh api repos/goreleaser/goreleaser-action/commits/v6 --jq .sha
    gh api repos/actions/checkout/commits/v7 --jq .sha
    gh api repos/actions/setup-go/commits/v7 --jq .sha
    gh api repos/actions/setup-node/commits/v7 --jq .sha
    gh api repos/actions/cache/commits/v4 --jq .sha
    gh api repos/actions/upload-artifact/commits/v7 --jq .sha
    gh api repos/actions/download-artifact/commits/v8 --jq .sha

A tag that names a release can also be read as `gh api repos/OWNER/REPO/git/ref/tags/TAG --jq .object.sha`; when that
object is an annotated tag, `gh api repos/OWNER/REPO/git/tags/SHA --jq .object.sha` gives the commit. Both ways must
give the same commit as the first command.

Then replace each `uses:` line, keeping the tag as a comment so that a reader (and an update tool) knows the version:

    - uses: vmactions/freebsd-vm@<40-character sha> # v1

Check before you commit:

    grep -n 'uses:' .github/workflows/*.yml | grep -v '@[0-9a-f]\{40\} # '

prints nothing when every action is pinned.

## Updating a pinned action

Read the action's release notes and the diff between the pinned commit and the new one
(`gh api repos/OWNER/REPO/compare/OLD...NEW --jq '.files[].filename'`), above all for `vmactions/freebsd-vm` and
`goreleaser/goreleaser-action`, then pin the new commit as above.
