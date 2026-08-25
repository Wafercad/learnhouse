# Wafercad service-integration token — LearnHouse fork change spec

**Status:** spec (2026-08-25). Target repo: this fork (`Wafercad/learnhouse`, AGPL-3.0).
**Consumer:** `eda-services/campus_service` (the Cloud Campus BFF). See the WCS-side design in
`eda-services/docs/CLOUD_CAMPUS_ARCHITECTURE.md` §5.2 (this is the "thin additive fork" it
refers to).

This change is **contained to the AGPL fork** and remains AGPL. `campus_service` calls it only
over HTTP (per `eda-services/docs/ADR-001-learnhouse-agpl-boundary.md`) — no code crosses the
boundary.

---

## 1. Why

WCC runs LearnHouse as a **single-org** (Community Edition) headless engine, with
`campus_service` as the sole tenant fence and a **pure BFF** (the browser never holds a
LearnHouse token). For that, `campus_service` must, using one platform credential, act on a
**specific learner's** learning records within the one campus org:

- **Write/read that learner's `trail`** (enrol a course, mark activity progress, read progress
  for reconciliation). Today trail endpoints are **strictly current-user** (`routers/trail.py`
  — every endpoint is `user=Depends(get_current_user)`, no user parameter) **and** `trails` is
  **not** in the API-token resource allowlist (`security/rbac/rbac.py:575`). So an org API
  token cannot touch trails at all, and cannot act for another user.

Everything else campus needs is **already supported** and needs **no change**:
- **usergroups** (batch ⇄ usergroup CRUD, add/remove members, link resources) — already in the
  API-token allowlist (`rbac.py:576`).
- **assignment submissions + grading** — `assignments` is already allowlisted, and those
  endpoints are already **user-addressable by path param** (`/assignments/{uuid}/submissions/
  {user_id}` and `.../grade`), so a service token with `assignments` rights can already read/
  grade a specific learner's submission. No on-behalf-of needed here.

So the entire fork change is: **let a flagged service token (a) reach `trails`, and (b) act on
behalf of a named user within its own org.**

## 2. Non-goals (explicitly not changing)

- **No EE / multi-org gate flip.** `is_multi_org_allowed()` / `ee_hooks.py` untouched; the
  deployment stays single-org, Community Edition.
- **No change to `SuperadminAPITokenUser`** (it is unwired outside `dev.py` — do not build on
  it) or to `PublicUser` semantics.
- **No change to the public per-user trail endpoints' behavior** when no on-behalf-of header is
  present — existing sessions/tokens behave exactly as today.
- No new cross-org capability. The service token stays **org-scoped** (bound to the one campus
  org), so `_verify_api_token_org_boundary` (`auth.py:430`) remains the hard second fence.

## 3. The change (minimal, additive, rebase-friendly)

Six small touch-points. Keep new logic in one new module and guard it with a config flag so
upstream merges stay clean.

### 3.1 Data — mark a token as service-integration
- **Migration:** add `apitoken.is_service_integration BOOLEAN NOT NULL DEFAULT false`.
- **Model (`db/users.py`, `APITokenUser` ~:134):** add field
  `is_service_integration: bool = False`.
- **`validate_api_token` (`security/auth.py:674`):** populate the new field from the row.

A "service token" is therefore just an ordinary **org-scoped** `lh_` API token with this flag
set — it keeps the org boundary and the per-action `rights` dict. A read-only service token
(rights → read only) is possible and encouraged for reconciliation-only credentials.

### 3.2 Allowlist — let service tokens reach `trails`
In `authorization_verify_api_token_permissions` (`security/rbac/rbac.py:575`), after building
`allowed_resource_types`, extend it **only for service tokens**:
```python
if getattr(api_token_user, "is_service_integration", False):
    allowed_resource_types = allowed_resource_types + ["trails"]
```
Normal org tokens are unaffected (still cannot touch trails). Org-boundary and rights checks
downstream are unchanged.

### 3.3 Act-on-behalf-of — new dependency `resolve_effective_user`
New module `security/service_integration.py`:
```python
# pseudo-spec — implement against real models
ON_BEHALF_HEADER = "X-On-Behalf-Of-User"   # value = LearnHouse user_uuid (preferred) or id

async def resolve_effective_user(request, db_session, user = Depends(get_current_user)):
    """If a service token supplies X-On-Behalf-Of-User, return that user as the effective
    principal (bounded to the token's org); otherwise return `user` unchanged."""
    obh = request.headers.get(ON_BEHALF_HEADER)
    if obh is None:
        return user                              # unchanged path — public/session/plain token
    if not (isinstance(user, APITokenUser) and user.is_service_integration):
        raise HTTPException(403, "on-behalf-of requires a service-integration token")
    target = await load_user_by_uuid_or_id(obh, db_session)
    if target is None:
        raise HTTPException(404, "on-behalf-of user not found")
    if not await is_org_member(target.id, user.org_id, db_session):   # userorganization
        raise HTTPException(403, "on-behalf-of user is not in the token's organization")
    await write_audit(db_session, actor=user, subject=target,          # §3.5
                      action=request.method, path=request.url.path)
    return PublicUser.from_user(target)          # a normal user principal for downstream
```
Returning a normal `PublicUser` means all downstream trail logic (`services/trail/trail.py`)
runs **exactly as it would for that learner** — `TrailRun.org_id`/`user_id` are stamped from
the course + effective user as today (`trail.py:266,507`); no change to trail internals.

### 3.4 Wire it into the trail router only
In `routers/trail.py`, swap the dependency on the record-bearing endpoints from
`get_current_user` → `resolve_effective_user`:
`api_start_trail`, `api_get_user_trail`, `api_get_trail_by_org_id`, `api_add_course_to_trail`,
`api_remove_course_to_trail`, `api_add_activity_to_trail`, `api_remove_activity_from_trail`.
No other router changes. (Assignments/usergroups routers are untouched — already sufficient.)

### 3.5 Audit
Every on-behalf-of call writes a `user_audit_event` row: `actor = token (id/name/
created_by_user_id)`, `subject = effective user id`, `action`, `resource path`, `org_id`,
timestamp. This is the "campus acted as learner X" trail (mirrors the audit expectation in
`eda-services/docs/ACCOUNT_ONBOARDING_AND_CAMPUS_PROVISIONING_DESIGN.md` §16).

### 3.6 Config + minting
- Config flag `WAFERCAD_SERVICE_INTEGRATION_ENABLED` (default **false**) gates §3.2–§3.4 — with
  it off, the fork behaves like stock CE. Set true in WCC deployments.
- Mint the token via a **superadmin-only** path (extend `cli.py` or a `require_superadmin`
  route — not the public API): create an org-scoped `lh_` token for the campus org with
  `is_service_integration=true` and the needed `rights` (usergroups rw, assignments rw, trails
  rw; or read-only for a reconciliation credential). Store it as a **secret** in
  `campus_service` config (never in code/logs; rotatable — constitution rules).

## 4. `campus_service` (consumer) contract

Every LH call from campus:
```
Authorization: Bearer lh_<service_token>          # org-scoped, is_service_integration
X-On-Behalf-Of-User: <lh_user_uuid>               # only on per-learner trail calls
```
`lh_user_uuid` is resolved from campus's `identity_link (account_id,user_id → lh_user_id)`
(architecture doc §4.2). campus writes progress **through** these endpoints and updates its own
`progress_projection` write-through, so instructor dashboards read the projection, not live
cross-user LH reads (architecture doc §7.B, §9). Usergroup and submission/grading calls use the
same token **without** the on-behalf header (those endpoints are already user-addressable).

## 5. Security invariants (must hold; test them)

1. On-behalf-of header on a **non-service** token → **403** (no privilege escalation for
   ordinary org tokens).
2. On-behalf-of target **outside the token's org** → **403** (org boundary intact; matters if
   the deployment ever grows past one org).
3. A plain org token **still cannot** touch `trails` (allowlist unchanged for non-service).
4. With the header **absent**, every existing endpoint behaves byte-for-byte as before.
5. Every on-behalf-of action produces exactly one audit row.
6. `WAFERCAD_SERVICE_INTEGRATION_ENABLED=false` ⇒ the flag/allowlist/dependency are inert
   (clean parity with upstream CE).

## 6. Rebase strategy (keep upstream merges cheap)

- New behavior lives in `security/service_integration.py`; edits to existing files are the
  **minimum**: one migration, one model field + its populate line, **one** conditional line in
  the allowlist, and the router `Depends` swaps. All guarded by the config flag.
- Do not refactor surrounding code. If upstream changes `authorization_verify_api_token_
  permissions` or the trail router, the conflict surface is a single line / a dependency name.

## 7. AGPL note

This change is authored **in** the AGPL fork and stays AGPL; offer the modified source to the
service's network users. `campus_service` consumes it only over HTTP (Bearer + header) and
incorporates no LearnHouse code — the arms-length boundary in ADR-001 is preserved.
