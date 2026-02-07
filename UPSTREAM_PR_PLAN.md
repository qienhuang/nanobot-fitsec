# Upstream PR Plan: FIT-Sec as an Optional Runtime Safety Layer

This repository is a security-focused fork of `HKUDS/nanobot` that adds a **runtime-level** safety layer ("FIT-Sec").

Goal: make it easy for upstream to **merge** the safety work without taking on a large refactor or changing default behavior.

Non-goals:
- This is **not** a proposal to replace upstream agent logic, providers, or prompt design.
- This is **not** a request to "require FIT" for normal nanobot usage.

## Design constraints (upstream-friendly)

1. **Opt-in**: default behavior remains unchanged unless the user enables FIT-Sec.
2. **Low-intrusion**: implement FIT-Sec as a wrapper/middleware around tool execution.
3. **Least surprise**: in non-strict mode, FIT-Sec should degrade gracefully (log/audit + allow) rather than break workflows.
4. **Auditable**: every deny/allow relevant to high-impact tools should be written to an append-only audit log.
5. **Small surface area**: upstream should be able to review a few files per PR, each with clear acceptance criteria.

## Proposed PR series (recommended)

### PR 1 — Add FIT-Sec core runtime (no behavior change)

**Purpose**: introduce the safety runtime as a self-contained module, not wired into the agent yet.

**Files (core)**:
- `nanobot/fitsec/` (runtime, gate, emptiness, policy, audit, types)
- `FITSEC.md` (brief design doc; no marketing)

**Acceptance criteria**:
- Importing `nanobot` works with FIT-Sec present, even if unused.
- FIT-Sec has no side-effects unless instantiated.
- Unit tests cover the gate/policy/audit invariants at the pure-python level (no LLM required).

**Why PR 1 first**:
- Upstream can review the safety model in isolation.
- No CLI changes, no new defaults.

---

### PR 2 — SecureToolRegistry middleware (still opt-in)

**Purpose**: provide a single integration point for safety checks at the tool-execution boundary.

**Files**:
- `nanobot/agent/tools/secure_registry.py`

**Core behaviors** (auditable):
- **Omega taxonomy** for tool blast radius: O0 (read), O1 (reversible write), O2 (irreversible).
- **Monitorability Gate** applies to high-impact tools (recommended: O1/O2 or at least O2).
- **Emptiness Window** can block commit-power while preserving cognition.
- **Policy engine** (default-deny for O2 without explicit approval).
- **Audit log** records allow/deny and the reason.

**Acceptance criteria**:
- All deny paths are audited (policy deny, gate fail, emptiness block).
- Strict mode behavior is clear:
  - `strict_mode=True`: deny on gate fail.
  - `strict_mode=False`: audit + allow (or audit + warn), but never "silently" allow.

---

### PR 3 — SecureAgentLoop (opt-in alternative loop)

**Purpose**: provide an opt-in agent loop using `SecureToolRegistry`, without altering the standard `AgentLoop`.

**Files**:
- `nanobot/agent/secure_loop.py`

**Acceptance criteria**:
- No changes required to the standard `AgentLoop`.
- Secure loop produces the same tool results as baseline on safe operations.
- Unsafe operations are blocked only when the policy/gate says so (and always audited).

---

### PR 4 — CLI flag + config wiring (user-visible, still default off)

**Purpose**: let users enable FIT-Sec without changing code.

**Implementation approach**:
- Add a CLI flag (examples):
  - `nanobot agent --fitsec` (enable secure loop)
  - `nanobot agent --fitsec-strict/--no-fitsec-strict`
  - `nanobot agent --fitsec-audit-path <path>`
- Keep defaults unchanged:
  - no flag → old loop → old behavior

**Acceptance criteria**:
- `nanobot agent` runs exactly as before unless `--fitsec` is set.
- Documentation includes a minimal "how to enable" block.

---

### PR 5 — Minimal reproducible safety demo + regression tests

**Purpose**: provide concrete evidence that FIT-Sec improves safety in at least one realistic scenario, without breaking safe usage.

**Recommended demo shape**:
- A prompt set where baseline tool use includes a clearly "unsafe" tool call (e.g., file write outside workspace, or high-impact exec).
- With FIT-Sec enabled, the same prompt triggers:
  - `DENY` for unsafe call (with audit entry),
  - while safe calls continue to work.

**Acceptance criteria**:
- A deterministic, CI-friendly test (no external APIs) for deny/allow semantics.

## What we can offer upstream

- A PR series that keeps each review small and logically separated.
- No changes to upstream default behavior.
- Clear failure semantics (strict vs permissive) plus audit trail.

## Local status in this fork (for reference)

The fork already contains:
- `nanobot/fitsec/` runtime
- `nanobot/agent/tools/secure_registry.py` middleware
- `nanobot/agent/secure_loop.py` opt-in loop

The remaining work to make upstream merging maximally convenient is primarily:
- tighten opt-in wiring (CLI/config),
- keep the integration surface minimal,
- add CI-friendly tests and a tiny reproducible demo.

