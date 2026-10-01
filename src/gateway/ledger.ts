/**
 * The ledger rules: how stored history becomes the AgentState the engine reasons over.
 *
 * The engine is pure and trusts the state it is handed; it never consults a clock to roll a
 * spend window. In the gateway that state comes from here and only from here. The agent never
 * supplies it, so it cannot claim an empty window or a clean call count.
 *
 * Two rules carry the weight:
 *
 *   - every decision is a call, whatever the verdict. Counting only allows would let an agent
 *     probe a sealed policy with denied requests forever, with no rate limit ever binding.
 *   - only an allow spends, and only a positive amount. A negative amount must never credit the
 *     window back; the engine already denies it, and this keeps the ledger honest regardless.
 */

import type { AgentState, Verdict } from "../policy/types.ts";

export function initialState(now: number): AgentState {
  return { spentInWindow: 0n, windowStartedAt: now, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
}

/**
 * The state as of `now`: the stored state with its window rolled if the window has expired.
 * Without a window length the window never rolls, so a per-window cap acts as a lifetime cap -
 * the conservative reading of a policy that names no window.
 */
export function stateAt(stored: AgentState, windowSeconds: number | undefined, now: number): AgentState {
  if (windowSeconds === undefined || windowSeconds <= 0) return stored;
  if (now - stored.windowStartedAt < windowSeconds * 1000) return stored;
  return { ...stored, spentInWindow: 0n, callsInWindow: 0, windowStartedAt: now };
}

export function afterDecision(state: AgentState, verdict: Verdict, amount: bigint | undefined): AgentState {
  const spends = verdict === "allow" && amount !== undefined && amount > 0n;
  return {
    ...state,
    callsInWindow: state.callsInWindow + 1,
    spentInWindow: spends ? state.spentInWindow + amount : state.spentInWindow,
  };
}
