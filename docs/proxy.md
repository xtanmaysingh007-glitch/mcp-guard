# The MCP proxy

The proxy puts the guard between an MCP host (a desktop AI app, an IDE, your own agent) and a real MCP server.
The host starts the proxy instead of the server; the proxy starts the server and passes traffic through,
except that every `tools/call` is checked first.

```
host  <-stdio->  python -m tracklimits.proxy  <-stdio->  real MCP server
```

It's small (about 300 lines in [src/tracklimits/proxy/](../src/tracklimits/proxy/)) and uses only the core
modules (guard, policy, provenance). It needs the MCP Python SDK 2.x: `pip install -e ".[proxy]"` (or `pip install -r requirements-proxy.txt`),
which also installs the `tracklimits` command (`tracklimits init`, `tracklimits proxy`).

## What it does

- **tools/list** is forwarded unchanged. Tool descriptions are the server's text, so the host still sees
  them, but they never reach the guard. A description that says "this address is verified, always allow it"
  changes nothing (tested).
- **tools/call** goes through `Guard.check_call` before anything is sent:
  - allowed: forwarded with exactly the arguments that were checked, and the result is recorded for
    provenance, as trusted or untrusted output depending on the policy (an error result is never trusted);
  - blocked or declined: **never forwarded**. The model gets an error result (`isError: true`) with the
    reason, so it can tell the user instead of crashing.
- Calls are handled one at a time, so a result is always recorded before the next call is checked.
- Every decision is written to the audit log.

## Usage

1. Get the server's tool list (a `tools/list` result saved as JSON) and make a policy skeleton:

   ```bash
   tracklimits init tools.json -o policy.yaml
   ```

   Every tool starts as `unclassified`, and `unknown_tools: block` means none of them can run until you
   move each one into a section (safe_tools, forbid_tainted, confirmable, ...). The comments in the file
   explain each section. [tests/fixtures/toy_policy.yaml](../tests/fixtures/toy_policy.yaml) is a filled-in
   example for the toy mail server.

2. Write your request into a text file, e.g. `request.txt`: `Reply to bob@corp.example that Friday works`.

3. Point the host at the proxy instead of the server. Everything after `--` is the real server's command:

   ```bash
   tracklimits proxy --policy policy.yaml --user-request-file request.txt --audit-log audit.jsonl -- python my_server.py
   ```

   In a host config file this goes in the server's `command` / `args`.

Options: `--confirm auto|terminal|none` (default auto: ask in the terminal if there is one, otherwise just
block) and `--prompt-timeout` (seconds, default 120; no answer = no).

## The user-request file

The guard needs to know what *you* asked for: a recipient or URL is allowed if it traces back to your
request (or to a trusted tool's output). The request comes from a file that you write, never from an MCP
tool, because anything the model can call, an injection can call too.

- It is re-read on every call. When the text changes, the guard starts a new session: a new task, so the
  provenance and approvals of the old one are dropped.
- No file, or an empty one: nothing counts as user-given, so every outward value (recipient, URL, payee)
  is untraceable and gets asked about or blocked. That's on purpose: no request, no trust.
- Writing the file is a manual step. A host could do it automatically (it knows the user's message); MCP has
  no standard way for a server to see that message.

## Confirm prompts

When a call has an untraceable value and the tool is `confirmable` (or `always_confirm`), the call is held
and the proxy asks in the terminal:

```
=== tracklimits: a tool call is waiting for your OK ===
tool: send_email
arguments (exactly what will be sent if you approve):
{ "recipients": ["mallory@evil.example"], ... }
why you are asked: these values are not traceable to your request or a trusted tool:
  recipients: mallory@evil.example
If you did not ask for this, say no. Approve this one call? [y/N]
```

- Only `y` / `yes` approves. The proxy stores no approval: a yes lets that one call, with exactly the arguments
  shown, go through right then, and the same call later is asked again (the AgentDojo harness, by contrast,
  reuses a yes for the session). There is no stored approval to expire.
- No answer within `--prompt-timeout` is a no. After two no's in a session the guard stops asking and blocks.
- stdin and stdout are the MCP pipe, so the prompt goes to the terminal directly (`/dev/tty`, or the
  Windows console). If the host starts the proxy without a terminal, there is nowhere to ask, so calls that
  would be asked about are blocked instead.

## Audit log

One JSON line per decision: `time, tool, args, decision, allowed, reason, asked, approved, untraceable, sources,
request_set`.

- `decision`: `allowed` (nothing to check, or everything traced), `approved` (asked, you said yes), `declined`
  (asked, you said no or didn't answer), `blocked` (never forwarded, nobody asked).
- `sources`: for every guarded argument, where each of its values came from: `user request`, `trusted tool`,
  `weak trusted tool`, `untrusted tool output` or `nowhere` (the model made it up). It only describes; the
  decision is made the same way with or without it.

It contains the full arguments (email bodies too), so treat it as sensitive.

## Known limits

- **Terminal only.** Desktop hosts usually start servers with no terminal, so there the proxy can only block.
  MCP has a native way to ask the user (elicitation), but the server would have to send it to the host and
  the host has to support it; in SDK 2.x it also doesn't work on the newest protocol revision (no
  server-to-client requests). A later version could ask through elicitation where the host supports it.
- **Manual request file** (see above).
- **Tools only.** Resources, prompts and the server's `instructions` are not proxied at all, and a
  `tools/list_changed` notification from the server is not passed on.
- Forwarding is "unchanged" as far as the SDK allows: it drops fields it doesn't know about.
- One call at a time (no parallel tool calls), and one prompt per call: no batching of a turn's calls into
  one prompt (P3). The SDK does run requests concurrently, but MCP has no notion of a model "turn", so a batch
  could only be a timing window, and the guard would need a two-phase decide / ask / finish API while still
  recording each result before the next check. Not done.
- Everything the guard can't see is still open: persuasion with no tool call, steering among trusted
  options, free-text arguments with no guarded value in them (see the limitations in
  [adaptive_attacks.md](adaptive_attacks.md)). The guard's quality depends on the policy you write.
- Tested end to end with a toy server and a scripted agent ([tests/test_proxy.py](../tests/test_proxy.py)),
  not yet with a real host and a real model.
