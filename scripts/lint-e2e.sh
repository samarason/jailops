#!/bin/sh
# The rules of the end-to-end scripts (scripts/ci-freebsd-e2e.sh, scripts/ci-freebsd-pf.sh): a pause that waits for a
# condition is a poll (waitfor, expect_retry, check_retry), not a number of seconds. A line that is only `sleep N` must say
# why with `# sleep-ok: reason`: the poll of a loop, a deadline that has to pass, a negative probe that has to give a
# packet its time. Run by `just check` and by the CI job.
set -eu
cd "$(dirname "$0")/.."
bad=$(grep -nE '^[[:space:]]*sleep[[:space:]]+[0-9]' scripts/ci-freebsd-e2e.sh scripts/ci-freebsd-pf.sh | grep -v '# sleep-ok: ' || true)
if [ -n "$bad" ]; then
	printf '%s\n' "$bad" >&2
	echo "lint-e2e: a bare sleep in an end-to-end script: wait for the condition (waitfor, expect_retry) or say why with '# sleep-ok: reason'" >&2
	exit 1
fi
echo "lint-e2e: ok"
