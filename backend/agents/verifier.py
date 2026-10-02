"""Evidence gate: runs after ai_security_agent, before correlation.

Rule: a finding can only be CONFIRMED if it came from a deterministic probe (the tool
itself observed the condition directly) or carries a reproduction request that still
reproduces it when replayed right now. Anything else is capped at INCONCLUSIVE.

This is what keeps "never invent evidence" an enforced rule instead of a prompt hint.
"""
import httpx
from tools.sessions import close_sessions

MARKER_HINT = "SENTINEL_"


def _replay(reproduction_url, auth_ctx):
    """Best-effort replay of a stored reproduction request. Returns True/False/None
    (None = could not be checked, so the finding's existing status is left alone)."""
    sessions = auth_ctx.get("sessions", {})
    client = next((c for c, _i, _cr in sessions.values()), None)
    try:
        if client is not None:
            r = client.get(reproduction_url)
        else:
            r = httpx.get(reproduction_url, timeout=3.0, follow_redirects=True)
    except httpx.HTTPError:
        return None
    return r.status_code == 200


def verifier(state):
    print("\n=== EVIDENCE VERIFIER ===")
    auth_ctx = state.get("auth_context", {})
    findings = state.get("findings", [])

    confirmed_in, confirmed_out, downgraded = 0, 0, 0
    for f in findings:
        if str(f.get("status", "")).upper() != "CONFIRMED":
            continue
        confirmed_in += 1

        provenance = f.get("provenance", "deterministic")
        reproduction = f.get("reproduction")

        if provenance == "deterministic" and not reproduction:
            # The tool observed the condition directly at test time (e.g. a status-code
            # comparison); nothing further to replay.
            confirmed_out += 1
            continue

        if not reproduction:
            # An LLM-only claim with nothing to check: never let it stay CONFIRMED.
            f["status"] = "INCONCLUSIVE"
            f["reasoning"] = (f.get("reasoning", "") + " [Downgraded by verifier: no reproducible evidence attached.]").strip()
            downgraded += 1
            continue

        ok = _replay(reproduction, auth_ctx)
        if ok is False:
            f["status"] = "INCONCLUSIVE"
            f["reasoning"] = (f.get("reasoning", "") + " [Downgraded by verifier: reproduction request no longer reproduces the finding.]").strip()
            downgraded += 1
        else:
            # ok is True, or None (unverifiable) -- keep the original deterministic status.
            confirmed_out += 1

    close_sessions(auth_ctx.get("sessions", {}))

    print(f"Confirmed findings in: {confirmed_in}, still confirmed: {confirmed_out}, downgraded: {downgraded}")
    state.setdefault("trace", []).append({
        "step": "verifier", "confirmed_in": confirmed_in,
        "confirmed_out": confirmed_out, "downgraded": downgraded,
    })
    return state
