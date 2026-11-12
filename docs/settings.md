# Policy settings

Every setting the guard reads from a policy file, its default, and why. Three columns of defaults, because
they differ on purpose:

- **built-in**: what you get when the key is missing from the YAML (or with `Policy()` in code);
- **AgentDojo**: what `src/tracklimits/policies/agentdojo.yaml` sets (all benchmark numbers use this file);
- **`tracklimits init`**: what the generated skeleton for a new MCP server starts with.

The proxy (`tracklimits proxy`) also overrides a few things on top of the file, listed at the end.

| setting | built-in | AgentDojo | `tracklimits init` |
|---|---|---|---|
| `mode` | `allowlist` | `allowlist` | `allowlist` |
| `trusted_tools` | none | user's own account data, calendars, contacts, directories (see file) | none (you decide) |
| `weak_trusted_tools` | none | contacts, channel/user lists, travel directories | none |
| `strict_trust` | `typed` | `typed` | `typed` |
| `forbid_tainted` | none | recipients, payees, URLs, participants, ... | none |
| `check_links_in` | none | email / message bodies | none |
| `outward_args` | none | where data, money or access leaves | none |
| `confirmable` | none | send_email, messages, invites, calendar tools, ... | none |
| `always_confirm` | none | delete_file, delete_email, cancel/reschedule_calendar_event | none |
| `user_identities` | none | emma.johnson@bluesparrowtech.com | none |
| `unknown_tools` | `allow` | `allow` | `block` |
| `safe_tools` | none | 34 read-only lookups | none |
| `approval_scope` | `value` | `value` | `value` |
| `approval_scope_by_tool` | none | `call` for send_email, DMs, channel messages, create/append file, post_webpage | none |
| `approval_ttl_calls` | `5` | `5` | `5` |
| `self_note_tools` | `send_email: [recipients, body]` | same (not in the file: default) | same (default) |
| `self_note_copy_words` | `6` | `6` | `6` |
| `self_note_min_digits` | `8` | `8` | `8` |
| `secret_args` | none | `update_password: [password]` | none |

## What each one does, and why the default is what it is

**`mode`** (`allowlist` / `taint`). Allowlist: a guarded argument must trace to the user's request or a trusted
tool's output, otherwise it is refused (default-deny). Taint: only values seen verbatim in untrusted data are
refused (a blocklist). Allowlist is the default because taint misses anything the model rewords or invents;
taint exists for comparison.

**`trusted_tools`**. Tools whose output is structured data the user owns (account details, the user's own
calendar). Only *whole values* count (an email field, a list item), never an address buried in a sentence.
Default empty: trusting a tool is a decision about who can write into it, so nobody gets trusted by accident.
The ablation `tracklimits_no_trusted` showed trusted tools buy utility, not security.

**`weak_trusted_tools`**. Trusted tools an attacker *can* write into indirectly (a contact list built from
received emails, channel names anyone can create). Must be a subset of `trusted_tools`. Their values count for
ordinary arguments; `strict_trust` decides about outward ones.

**`strict_trust`** (`off` / `typed` / `full`). How far weak trusted values count for outward arguments: `off`
fully, `typed` not for emails / URLs / IBANs (plain names like a channel still pass), `full` not at all.
`typed` is the project default since 2026-11-09: it blocked all four adaptive "weak trust" attacks (B1-B3) at
the cost of one workspace task, while `full` dropped slack utility from 11/21 to 4/21 (perfect agent). It is
also the fail-safe fallback since 2026-11-11: a policy file that leaves the key out, or writes it with no
value, gets `typed` (before, it silently got `off`). `off` must be written explicitly (`strict_trust: off`
or `false`).

**`forbid_tainted`** (tool -> argument names). The arguments that are checked. Default empty, because which
arguments matter is tool-specific. ID-style arguments (file_id, email_id) are deliberately not here: an ID
can't be traced (file 13 from an injection looks like file 11 from the user), see `always_confirm`.

**`check_links_in`** (tool -> free-text arguments). Free text is not checked as a whole (an email body is
always new text), but any link, email address or IBAN inside it must trace. The ablation without it leaked a
phishing link in a DM body; that is the one security win we measured from a single component.

**`outward_args`** (tool -> arguments). Where data, money or access leaves the user: recipients, payees,
invites, URLs to visit. Used only by `strict_trust` (links inside `check_links_in` count as outward too).

**`confirmable`**. Tools where an untraceable value is *shown to the user* instead of refused (confirm mode
only; plain mode always refuses). Default empty: asking is only useful where a human can judge the value.
`send_money` is deliberately not confirmable in the AgentDojo policy (a payee you can't trace isn't something
to wave through).

**`always_confirm`**. Tools that always go to the user, even with clean arguments, because what they act on
can't be traced (they take only IDs: delete, cancel, reschedule). Plain mode blocks them. Cost measured in the
ground truth of all 4 suites: workspace user tasks 7, 35 and 38 can't succeed under plain mode.

**`user_identities`**. The user's own addresses, treated as user-given in every session (otherwise "invite me to
my own event" is untraceable: AgentDojo has no "who am I" tool). Known side effect: an attack step that mails
the user's own address passes; its exfiltration step to the attacker is still checked.

**`unknown_tools`** (`allow` / `block`). What happens to a tool the policy never mentions. Built-in `allow` and
the AgentDojo file says `allow` so that every earlier benchmark number stays comparable; `init` and the proxy
say `block` (default-deny): a new tool that might send, pay or delete can't run until someone classifies it.
Unknown tools are blocked even in confirm mode (not asked).

**`safe_tools`**. Read-only lookups listed on purpose, so `unknown_tools: block` doesn't stop them. Their output
is still untrusted. `create_file` / `append_to_file` are left out of the AgentDojo list on purpose: they write.

**`approval_scope`** (`value` / `call`) and **`approval_scope_by_tool`**. What a "yes" in confirm mode covers.
`value`: that value in that argument, for the rest of the session. `call`: only that exact call (since P2 the
identical call is not asked again this session either way, so neither scope is one-time). Default
`value` (fewer prompts), with `call` for tools whose free text the user should see every time: a yes to
"email Carol draft 1" is not a yes to "email Carol draft 2". Measured on the slack logs: per-tool call scope
roughly doubled the prompts; the de-duplication P2 (an exact call approved once isn't asked again) brought
clean slack from 2.38 to 1.43 prompts per task.

**`approval_ttl_calls`** (`5`). An approval given *ahead* of a call (`Guard.approve_call`, for asynchronous
approval) expires after this many checked calls, and is used at most once. Nothing calls `approve_call` except
tests: neither the AgentDojo harness nor the proxy uses it.

**`self_note_tools`, `self_note_copy_words`, `self_note_min_digits`** (message to self, 2026-11-11). For the
listed tools (`tool: [recipient arg, text arg, ...]`), when *every* recipient is one of `user_identities`, the
text args may not copy `self_note_copy_words` words of untrusted tool output (not in the user's request), nor
carry a digit run of `self_note_min_digits`+ digits that traces to neither the request nor a trusted tool.
Why: `user_identities` makes the user's own address user-given, so an attacker's ransom note mailed "to
yourself" used to pass (workspace injection tasks 9 and 12, seen live 12 times). Missing or empty keys get the
defaults above (fail-safe); `0` switches that half off. It closes the observed variant only: a paraphrase
without digits, or a number written in words, still passes (docs/adaptive_attacks.md, G).

**`secret_args`** (tool -> arguments; review R2, 2026-11-12). Secrets such as a new password. Such a value
must equal a token the user wrote in quotes in the request, exactly (`'1j1l-2k3j'`). Before, any word of the
request counted ("please" passed as a password) and anything under three characters wasn't checked at all.
Other values matched against the request need at least three characters and a word that isn't a stop word.

## Fixed in code (not in the policy file)

- `PLAIN_BLOCK_RETRIES = 2` (guard.py): the same refused call gets the normal reason twice, then a blunt "already
  refused, don't retry" (small models looped on blocks; one workspace task hit 61).
- `MAX_DECLINES = 2` (guard.py): after two declined prompts in a session the guard stops asking and blocks every
  untraceable value (an attacker can't wear the user down with prompts).

## Size caps on tool output (review R8, 2026-11-12)

Fixed in code (`provenance.py`), so hostile output can't stall the guard (40,000 characters of one token used
to take about 16 s):

- **Untrusted output** is scanned as whitespace tokens, each cut to `UNTRUSTED_TOKEN_CAP` = 2,048 characters.
  A link hidden past that point in one giant token isn't seen there.
- **Trusted output**: only the first `TRUSTED_MAX_LINES` = 2,000 lines and `TRUSTED_MAX_CHARS` = 200,000
  characters become trusted values. Anything after the cap is recorded as untrusted, so it can't vouch for a
  value (fail closed): a payee on line 2,001 of a trusted list has to come from somewhere else.

Measured on the dev laptop: 1 MB of hostile output (long tokens, runs of spaces, 40,000 distinct emails or URLs)
is recorded in 0.2 to 0.9 s, trusted or not.

## What the proxy changes on top of the file

- `unknown_tools: block` if the file doesn't set it.
- `approval_scope` forced to `call` for every tool, and no approval is stored (`Guard(reuse_approvals=False)`):
  each guarded call is asked when it happens, a yes lets exactly that call through right then, and the same call
  later is asked again. An unanswered prompt is a no after `--prompt-timeout` (120 s); that is a prompt timeout,
  not an approval expiry.
- No request file, or an empty one: nothing counts as user-given.
