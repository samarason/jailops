package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

// Explanation documents one API error code.
type Explanation struct {
	Code  api.Code `json:"code"`
	Cause string   `json:"cause"`
	Fix   string   `json:"fix"`
}

// explanations has one entry for every code in sdk/api/errors.go. A test
// parses that file and fails when a code is missing here.
var explanations = []Explanation{
	{api.CodeInvalid, "The server rejected the request: a field is missing, malformed or out of range.", "Read the message, correct the named value (the message names the flag where there is one) and retry."},
	{api.CodeNotFound, "The named object does not exist on this host (objects of jails and snapshots are per host).", "List the kind to see the names, check --host and --remote, and check the spelling."},
	{api.CodeAlreadyExists, "An object of that kind and name already exists.", "Pick another name, or edit the existing object."},
	{api.CodeConflict, "The object changed on the server after you read it (stale generation, HTTP 412), or another object already holds what you asked for (the message names it).", "For a change made in the meantime: read the object again and repeat the change ('edit' commands do this for you). Otherwise free what the message names first."},
	{api.CodeUnauthorized, "The server did not accept your credential: no token, an expired or revoked token, or an unknown certificate.", "Check the token with 'jailops remote list' and 'jailops doctor'; create a new token on the server if needed."},
	{api.CodeForbidden, "Your credential is valid but its role does not allow this action.", "Ask an administrator for a token with a higher role (operator for lifecycle, admin for configuration). A network or storage that is not granted to the project is granted by a global admin: 'jailops network grant NET --project P', 'jailops project set P --storage NAME'."},
	{api.CodeUnsupported, "The server does not implement this feature, or a missing API extension.", "Upgrade the server, or use a different command; 'jailops server info' lists the extensions."},
	{api.CodeBusy, "Another operation holds a lock on the resource, or the server is temporarily overloaded.", "Wait for the running operation ('jailops op list') and retry."},
	{api.CodeInternal, "The server failed in a way the client cannot fix.", "Retry once, then report the request id shown with the error and check the server log."},
	{api.CodeQuotaExceeded, "Creating or growing this object would take the project over one of its quotas (jails, CPU, memory, PIDs, addresses or storage).", "See the usage with 'jailops project show NAME', free something up, or ask a global admin to raise the quota with 'jailops project set NAME --max-...'."},
	{api.CodeIPConflict, "The requested address is already used by another jail or is outside the network range.", "Use 'auto' or another address; 'jailops network leases NAME' shows what is taken."},
	{api.CodePoolExhausted, "The network has no free addresses left in its range.", "Widen the range of the network or remove unused jails."},
	{api.CodeImageInUse, "A jail still uses this image or image generation.", "Upgrade or delete the jails listed in the message, then retry."},
	{api.CodeDataLoss, "The operation would discard data and was sent without confirmation.", "Check what would be lost (the CLI shows the bytes written) and confirm by typing the jail name or with --confirm-data-loss."},
	{api.CodeVersionSkew, "The client, hub and host run API versions too far apart for this call.", "Upgrade the older side; 'jailops server info' shows both versions."},
	{api.CodeNotLeader, "This node is not the cluster leader and cannot accept the change.", "Retry against the leader named in the error detail, or through the hub."},
	{api.CodeNoQuorum, "The cluster has lost its quorum and cannot commit changes.", "Restore enough nodes to form a majority; reads keep working."},
	{api.CodeUnverified, "The feature needs FreeBSD or a kernel facility that this host does not provide or that was never proven there.", "Run the host on FreeBSD 15.1 or later with the facility enabled; see the unverified list in the documentation."},
	{api.CodeZFSIncompatible, "The ZFS pool or dataset lacks a feature the operation needs.", "Upgrade the pool features ('zpool upgrade') on both ends of the transfer."},
	{api.CodeChainBroken, "A backup chain has a missing or corrupt link, so later snapshots cannot be restored from it.", "Run 'jailops backup verify' and take a new full backup."},
	{api.CodeMergeConflict, "The /etc merge during an upgrade needs a human; the jail stays on the old generation.", "Resolve the listed files in the jail, then run 'jailops jail upgrade' again."},
	{api.CodeRateLimited, "Too many failed authentication attempts from this source.", "Wait a few minutes and retry with the correct credential."},
	{api.CodeKeyNotEscrowed, "A raw backup was refused because its key has no recoverable escrow.", "Escrow the backup key first, then repeat the backup."},
	{api.CodeMaintenance, "The backup node is read-only or offline for maintenance.", "Retry later; 'jailops backup target list' shows which target is affected."},
	{api.CodeMissingChunks, "A backup commit refers to chunks the repository does not have.", "Run the backup again so the missing chunks are uploaded; this is normal after an interrupted run."},
	{api.CodeLeaseExpired, "The backup session timed out or was closed by the node before it finished.", "Run the backup again; a slow link may need a longer session on the node."},
	{api.CodeNotManaged, "JailOps does not manage this part of the host: jailopsd.yaml or priv.conf does not enable the module.", "Add the lines the hint names and restart both services, or change the host by hand (docs/appliance.md). It exits 6, like unsupported."},
	{api.CodePlaintextDenied, "A backup node target would receive unencrypted data and the policy does not allow plaintext.", "Enable backup encryption, or set allow_plaintext on the target if that is intended."},
	{api.CodeLocked, "An encrypted volume of the jail waits for its passphrase (after a host boot or a lock); a locked jail does not start.", "Run 'jailops volume unlock NAME' for the volume the error names (add --start to start the jail at once); a jail due for autostart starts after the unlock."},
	{api.CodeStopForced, "A stop that did not finish within its budget was forced: the jail was removed without its stop commands and its processes were killed.", "See the console log of the jail (/var/log/jailops/jail_<project>_<name>_console.log) for what still ran; a service that needs longer says so with boot.stop_timeout (jailops config set JAIL boot.stop_timeout 60)."},
	{api.CodeBadPassphrase, "The passphrase of the encrypted volumes is wrong; after five wrong ones in a row unlocks are refused for 30 seconds.", "Type the passphrase again. A forgotten passphrase cannot be recovered: the data of the volume is lost (docs/storage.md)."},
}

func explainFor(c api.Code) (Explanation, bool) {
	for _, e := range explanations {
		if e.Code == c {
			return e, true
		}
	}
	return Explanation{}, false
}

func (a *app) explainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain [CODE]",
		Short: "Explain an error code: its cause and how to fix it",
		Long: `Every error the server returns carries a stable code. explain prints the
cause and the usual fix of one code, or a table of all codes when none is given.

The exit status of jailops depends on the code: 2 usage or invalid request, 3
authentication, 4 not found, 5 conflict, 6 unsupported or not managed, 7 internal,
1 anything else (the daemon cannot be reached, a confirmation was declined).

Confirmations come in three kinds, and the flags are not interchangeable:
-y answers a yes/no question (deleting a policy, a sink, a token); it never
answers a data-loss question. Data loss (deleting a jail, rolling one back over
its data, restoring over a jail) needs the typed name or --confirm-data-loss.
--confirm-lockout and --confirm-replace accept a risk that is not data loss and that the command cannot check
for you, such as a host firewall change whose lock-out check cannot run or
replacing a public certificate with the self-signed one. --force means one thing:
do not wait for a graceful shutdown (stop, restart, stop-all).`,
		Example: `jailops explain
jailops explain data_loss_unconfirmed
jailops explain not_found -o json`,
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var codes []string
			for _, e := range explanations {
				codes = append(codes, string(e.Code))
			}
			return codes, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				rows := make([][]string, 0, len(explanations))
				for _, e := range explanations {
					rows = append(rows, []string{string(e.Code), strconv.Itoa(exitForCode(e.Code)), e.Cause, e.Fix})
				}
				return a.emit(explanations, nil, func() ([]string, [][]string) {
					return []string{"CODE", "EXIT", "CAUSE", "FIX"}, rows
				}, func() []string {
					var n []string
					for _, e := range explanations {
						n = append(n, string(e.Code))
					}
					return n
				})
			}
			e, ok := explainFor(api.Code(args[0]))
			if !ok {
				return api.Errorf(api.CodeNotFound, "unknown error code %q", args[0]).WithHint("run 'jailops explain' for the list of codes")
			}
			if a.format != fmtTable {
				return a.emit(e, nil, nil, func() []string { return []string{string(e.Code)} })
			}
			w := a.env.Stdout
			fprintf(w, "%s\n\n", e.Code)
			fprintf(w, "Cause:  %s\n", e.Cause)
			fprintf(w, "Fix:    %s\n", e.Fix)
			fprintf(w, "HTTP:   %d\n", e.Code.HTTPStatus())
			fprintf(w, "Exit:   %s\n", fmt.Sprint(exitForCode(e.Code)))
			return nil
		},
	}
}
