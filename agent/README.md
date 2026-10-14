# agent/ — bản đồ năm file · map of the five files

*Bạn sở hữu toàn bộ thư mục này (RULES.md mục 1). Đọc bảng dưới TRƯỚC khi
sửa bất cứ file nào — nó nói mỗi file quyết định gì, bị chấm ở đâu trong
trace, và cứu bạn khỏi lớp lỗi nào trong 17 lớp (CONTRACTS.md mục 6.1).*
*You own this entire directory (RULES.md section 1). Read the table below
BEFORE editing any one file — it says what each decides, where in the
trace it is actually scored, and which of the 17 rubric classes
(CONTRACTS.md section 6.1) it stands between you and.*

Read them in this order the first time: `gateway.py` (the control plane —
everything else plugs into it), `strategy.py` (routing and budget policy),
`guardrails.py` (what your `ANSWER` should
pass before it ships), `telemetry.py` (how you'll ever know any of this is
working), `prompt.md` (the one your model actually reads).

---

## The map

| File | What it decides | What it's scored on | Defect classes it can save you from |
|---|---|---|---|
| **`gateway.py`** | For every MCP/A2A/DISCOVER command: ROUTE (which replica/tool), ADMIT (let it through at all), AUTHORIZE (does it belong to `ctx.act`), BUDGET (can the whole duel afford this mask). Returns a `Decision`; never executes anything itself. | The **arena's own** `command` / `decision` / `enforced` / `tool_call` L1 events, built around the `Decision` you returned (CONTRACTS.md section 5) — never anything you claim happened. This is the ONE file whose output a prosecutor's `enforcement_failure` claim points straight at. | `enforcement_failure` **10** · `authority_exceeded` **10** · `write_violation` **8** · `stale_read` **8** (via ROUTE) · `protocol_misuse` **6** · `wasteful` **3** (via BUDGET) |
| **`strategy.py`** | Policy helpers for routing, deprecation, leases, field masks, delegation decisions, caching, and budget pacing. `gateway.py` applies routing and budget helpers during every decision. | The same `command` / `tool_call` events as `gateway.py`, plus your own credit trajectory (`GatewayContext.credits` across all 10 rounds). | `wasteful` **3** · `protocol_misuse` **6** (lease/mask discipline) · `stale_read` **8** (replica choice) |
| **`guardrails.py`** | Checks answer grounding, scans untrusted text for injection patterns, redacts supplied private values and common direct identifiers, checks numeric literals against source text, and supports abstention on unsafe or incomplete drafts. | The `answer` L1 event (`text`, `cited_anchors`) the arena hands your opponent's prosecutor on prosecution (CONTRACTS.md section 5.4). | `ungrounded` **5** · `fabricated_citation` **8** · `hallucination` **7** · `guardrail_breach` **8** · `privacy_leak` **8** · `unsupported_precision` **4** · partial credit toward `non_responsive` **4** / `incoherent` **4** via abstaining instead of guessing |
| **`telemetry.py`** | Nothing scored, by design — `ctx.emit` wrappers for YOUR OWN reasoning trail. | **Never.** `own_telemetry` events are producer-stamped `student`, and CONTRACTS.md section 5.4 strips every one of them before your opponent's prosecutor ever sees the trace. No referee detector reads this file's output, ever. | None directly — but it is how you catch every OTHER row in this table's failures on your OWN runs (via `spar.py`/your own tests) before a real prosecutor catches them on a live one. |
| **`prompt.md`** | The model's own live reasoning: turn planning across the 4-iteration/20-second/100-credit budget, tool policy, citation and refusal rules, privacy protection, and handling source conflicts. Layered ON TOP of `kit.loop.prompt`'s harness grammar, never replacing it. | `model_turn.action_raw` — indirectly everything, since every `Command` and the final `ANSWER` trace back to what the model actually chose to do here. | `unflagged_conflict` **6** · `overreach` **5** · `incoherent` **4** · `non_responsive` **4** · `guardrail_breach` **8** |

---

## Reading the weights

Seventeen classes, five families (CONTRACTS.md section 6.1) — reproduced
here for orientation, not as a substitute for the source:

| Family | Classes and weights |
|---|---|
| **A · Infrastructure** | `enforcement_failure` 10 · `stale_read` 8 · `write_violation` 8 · `protocol_misuse` 6 |
| **B · Truth** | `wrong_answer` 8 · `fabricated_citation` 8 · `hallucination` 7 · `ungrounded` 5 · `unsupported_precision` 4 |
| **C · Safety** | `authority_exceeded` 10 · `guardrail_breach` 8 · `privacy_leak` 8 |
| **D · Quality** | `unflagged_conflict` 6 · `overreach` 5 · `incoherent` 4 · `non_responsive` 4 |
| **E · Economy** | `wasteful` 3 |

`enforcement_failure` and `authority_exceeded` are the two heaviest classes
in the whole rubric, and both are `gateway.py`'s to lose — that is the
Day 26 thesis, stated plainly in FINAL-PLAN.md: *"what your infrastructure
enforced, not what your agent happened to say."* `wrong_answer` (weight 8)
is notably absent from every "saves you from" column above: it is graded
structurally against `truth.json` field by field (CONTRACTS.md section 7),
never by string equality on prose — no amount of guardrail code fixes an
answer that is simply wrong about `course_day` or `track`. Getting the
facts right is still your job; these five files are what keeps you from
losing points on a RIGHT answer delivered the wrong way.

---

## One file, one job — don't blur them

A common mistake worth naming early: putting authorization logic in
`strategy.py` because "that's where the smart decisions live", or putting
budget pacing in `guardrails.py` because "that's about being careful too".
Keep the boundary CONTRACTS.md itself draws: `gateway.py` is the only file
whose return value the arena ever acts on for an MCP/A2A/DISCOVER command
— `strategy.py` and `guardrails.py` are libraries `gateway.py` (or your own
answer-assembly code) calls INTO, not parallel enforcement points. Two
gateways cannot both be authoritative; one `Gateway.decide` is.
