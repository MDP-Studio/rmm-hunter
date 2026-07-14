# Watch Preview And Active Defense

Date: 2026-05-21

This document defines the documentation-level contract for RMM Hunter Watch Preview and Active Defense. It is intentionally conservative. Watch helps notice changes and record response decisions. It does not claim to prevent breaches.

## Goals

- Detect meaningful changes after a known scan state.
- Keep a local checkpoint store for baseline comparison.
- Keep local alert history and action history.
- Notify through Discord webhook plus local history as the first alert channel.
- Offer active response only through deterministic policy gates.
- Keep every response auditable and reversible where possible.

## Non-Goals

- No breach-prevention claim.
- No automatic file deletion in the first release.
- No bundled KAPE, Sysmon, or third-party collection tools.
- No silent installation of services, scheduled tasks, or helper tooling.
- No arbitrary AI command execution.
- No AI override of severity, confidence, verdict, or response-mode approval.

## Watch State

Watch mode should store state locally on the endpoint:

| Store | Purpose |
| --- | --- |
| Checkpoints | Last known scan state used for delta comparison. |
| Alert history | Alerts raised from new, changed, or reconciled evidence. |
| Action history | Proposed, approved, skipped, failed, completed, and rolled-back actions. |

The stores may contain sensitive local evidence references, such as usernames, paths, service names, task names, timestamps, and finding summaries. They should be treated like scan reports.

## Monitoring Model

Watch uses hybrid monitoring:

- Near-real-time delta checks watch selected local sources for new or changed evidence.
- Full reconciliation scans run on a slower cadence to catch missed events, delayed logs, unavailable sources, or watcher gaps.
- Optional Sysmon support can improve process and network context when the user has installed or approved it.

Delta checks should be treated as an alerting accelerator, not the only source of truth. Full reconciliation remains necessary because Windows logs, service state, scheduled tasks, and endpoint protection data can be delayed, unavailable, or changed outside a watched path.

## Setup Consent

Setup must ask before enabling persistent helpers or external alerting.

User approval is required before:

- installing or registering a Watch scheduled task
- installing or registering a service wrapper
- enabling Discord webhook alerting
- installing, configuring, or connecting Sysmon
- importing third-party output

RMM Hunter does not bundle KAPE or third-party collection tools. If a user imports KAPE output, RMM Hunter reads the user-supplied output and records the source context.

## Alert Channel

The first alert channel is:

- local alert history
- Discord webhook notification when configured

Discord webhook URLs are secrets. Alert payloads should be compact and should not include raw report files. The local report remains the technical source of truth.

### Discord Webhook Setup

To create a Discord webhook:

1. In Discord, open the server channel that should receive RMM Hunter alerts.
2. Open channel settings, then **Integrations**, then **Webhooks**.
3. Create a webhook, name it `RMM Hunter Watch`, choose the alert channel, and copy the webhook URL.
4. Paste the URL into the RMM Hunter Watch tab, enable Discord alerts, then send a test alert. The test button saves the current Watch policy before sending.

Use a private alert channel and treat the webhook URL like a password. RMM Hunter accepts only official Discord webhook URLs beginning with `https://discord.com/api/webhooks/` or `https://discordapp.com/api/webhooks/`.

## Response Modes

| Mode | Default | Intended behavior |
| --- | --- | --- |
| `alert_only` | No | Record and notify only. No active response runs. |
| `approval_required` | Yes | Propose a response, but require user approval before running it. |
| `daytime_auto` | No | During configured support hours, allow only soft containment that passes policy gates. |
| `night_auto` | No | Outside support hours, allow guarded containment only for high-confidence alerts that pass stricter policy gates. |

`approval_required` is the default because RMM tools can be legitimate. Auto modes must be opt-in and visibly reversible where possible.

The current policy engine enforces configured support hours before any auto action. It accepts `local` or `UTC` timezones, ISO weekdays 1 through 7, and 24-hour `HH:MM` boundaries, including overnight windows. Invalid or missing time policy fails closed to operator approval.

## Policy Gates

Every response action must pass deterministic policy gates before it is offered or run.

Minimum gate inputs:

- response mode
- finding severity
- finding confidence
- evidence strength
- evidence source
- support-hours context
- known allowlist or expected-admin context
- action reversibility
- action allowlist for that finding type

Policy gates must fail closed. If evidence is missing, confidence is low, the action is not allowlisted, or the selected mode does not permit the action, the result should be alert and review only.

## AI Copilot Boundaries

AI Copilot can:

- explain an alert in plain English
- rank proposed next steps
- choose from pre-approved actions after deterministic policy gates have already allowed them
- summarize why an action requires approval or was blocked

AI Copilot cannot:

- run arbitrary commands
- invent a new response action
- override severity, confidence, or verdict
- bypass `approval_required`
- lower a policy gate
- delete files or remove evidence

The deterministic scanner report and policy engine remain the authority. AI output is advisory and constrained.

## Active Response Rules

Active response actions must be:

- pre-approved by policy
- audited
- reversible where possible
- tied to a specific alert
- visible in action history
- blocked when the policy gate fails

The first release must never delete files automatically. Evidence preservation matters more than cleanup. Collection, notification, and reversible containment are preferred.

Examples of response categories that may be considered after policy gating:

- collect additional evidence
- stop a suspicious service
- pause or disable a suspicious scheduled task
- disable a suspicious startup entry
- add a local firewall block rule
- open a guided approval prompt

These examples are not blanket permissions. Each action still needs a specific implementation, policy entry, audit record, and rollback path where possible.

## Audit Record

Each action-history entry should include:

- timestamp
- alert ID
- response mode
- policy decision
- selected action
- user approval state, when applicable
- command or API category, without exposing secrets
- result
- error message, when applicable
- rollback guidance or rollback result, when available

Audit records should avoid storing secrets, webhook URLs, API keys, or raw event payloads unless explicitly needed for local investigation.

## First Release Boundaries

For the first Watch Preview release:

- keep `approval_required` as the default
- keep deletion disabled
- keep Discord webhook and local history as the first alert channel
- make helper installation opt-in
- keep Sysmon optional
- document gaps honestly
- avoid claims that Watch prevents compromise
