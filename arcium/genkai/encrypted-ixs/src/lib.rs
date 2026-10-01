//! GENKAI policy circuits.
//!
//! One confidential instruction, evaluate_policy: it evaluates a sealed policy against a
//! plaintext request and reveals only a verdict code and a bitmask of the rules that fired -
//! or, when the caller asks for verdict-only disclosure, the verdict and a zero mask. The mask
//! is computed either way and the choice is a plaintext input, so the two modes cost the same
//! and the zero mask carries no information about the policy.
//!
//! The policy arrives as Enc<Shared, SealedPolicy>, read straight from the on-chain PolicyRecord.
//! It is encrypted under a one-time x25519 key the operator generates for the upload and then
//! discards, so once it is on chain only the MXE cluster can decrypt it. The operator wrote the
//! policy and needs no key to know it; nobody else can recover it from the ciphertext.
//!
//! This file mirrors src/mxe/circuit.ts in the TypeScript core rule for rule, and that model is
//! held to the plaintext engine by a 20,000-case differential test. Every rule is evaluated on
//! every call and no control flow depends on a secret, so the work the cluster does - and
//! anything observable about it - is the same whatever the policy says.
//!
//! The struct layouts are the wire format. SealedPolicy's field order must match flattenPolicy
//! in src/mxe/encoding.ts exactly; changing either requires a new circuit id.

use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    /// A policy in fixed-width form. Each list is (present, count, items); slots at or beyond
    /// count are ignored, so the ciphertext length never reveals how many entries there are.
    pub struct SealedPolicy {
        tools_present: bool,
        tools_count: u8,
        tools: [u128; 8],
        counterparties_present: bool,
        counterparties_count: u8,
        counterparties: [u128; 16],
        clusters_present: bool,
        clusters_count: u8,
        clusters: [u128; 4],
        programs_present: bool,
        programs_count: u8,
        programs: [u128; 8],
        mints_present: bool,
        mints_count: u8,
        mints: [u128; 8],
        mint_caps_present: bool,
        mint_caps_count: u8,
        mint_cap_keys: [u128; 8],
        mint_cap_values: [u64; 8],
        max_per_action_present: bool,
        max_per_action: u64,
        max_per_window_present: bool,
        max_per_window: u64,
        max_calls_present: bool,
        max_calls: u64,
        drawdown_present: bool,
        drawdown_halt: u64,
        escalate_present: bool,
        escalate_above: u64,
        hours_present: bool,
        hour_start: u16,
        hour_end: u16,
        days_present: bool,
        days_mask: u8,
    }

    fn member8(items: [u128; 8], count: u8, x: u128) -> bool {
        let mut found = false;
        for i in 0..8 {
            found = found | (((i as u8) < count) & (items[i] == x));
        }
        found
    }

    fn member16(items: [u128; 16], count: u8, x: u128) -> bool {
        let mut found = false;
        for i in 0..16 {
            found = found | (((i as u8) < count) & (items[i] == x));
        }
        found
    }

    fn member4(items: [u128; 4], count: u8, x: u128) -> bool {
        let mut found = false;
        for i in 0..4 {
            found = found | (((i as u8) < count) & (items[i] == x));
        }
        found
    }

    fn bit(fired: bool, index: u32) -> u32 {
        if fired {
            1u32 << index
        } else {
            0u32
        }
    }

    /// amount <= cap, for a signed amount (sign + magnitude) against an unsigned cap.
    fn amount_at_most(negative: bool, magnitude: u64, cap: u64) -> bool {
        negative | (magnitude <= cap)
    }

    /// spent + amount <= cap, in u128 so the sum cannot overflow.
    fn window_at_most(negative: bool, magnitude: u64, spent: u64, cap: u64) -> bool {
        let spent = spent as u128;
        let magnitude = magnitude as u128;
        let cap = cap as u128;
        if negative {
            spent <= cap + magnitude
        } else {
            spent + magnitude <= cap
        }
    }

    /// Returns (verdict, mask): verdict 0 allow, 1 deny, 2 escalate; bit i of mask is rule i in
    /// RULE_ORDER (src/mxe/circuit.ts), bit 17 being escalation. With disclose_rules false the
    /// mask is 0, so the revealed output names the verdict and nothing about which limit bound.
    #[instruction]
    pub fn evaluate_policy(
        policy: Enc<Shared, SealedPolicy>,
        tool_id: u128,
        has_counterparty: bool,
        counterparty_id: u128,
        has_amount: bool,
        amount_negative: bool,
        amount_magnitude: u64,
        is_solana: bool,
        solana_valid: bool,
        cluster_id: u128,
        program_id: u128,
        mint_id: u128,
        minute_of_day: u16,
        day_of_week: u8,
        revoked: bool,
        spent_in_window: u64,
        calls_in_window: u64,
        drawdown_from_peak: u64,
        disclose_rules: bool,
    ) -> (u8, u32) {
        let p = policy.to_arcis();

        let mut cap_found = false;
        let mut cap = 0u64;
        for i in 0..8 {
            let hit = ((i as u8) < p.mint_caps_count) & (p.mint_cap_keys[i] == mint_id);
            cap_found = cap_found | hit;
            cap = if hit { p.mint_cap_values[i] } else { cap };
        }

        let non_positive = !has_amount | amount_negative | (amount_magnitude == 0);
        let cap_gate = solana_valid & p.mint_caps_present & has_amount;
        // Shifts in a circuit must be by a constant, so test each of the seven days in turn.
        let mut day_allowed = false;
        for d in 0..7 {
            day_allowed = day_allowed | ((day_of_week == (d as u8)) & (((p.days_mask >> d) & 1) == 1));
        }
        let day_fails = p.days_present & !day_allowed;
        let in_hours = (minute_of_day >= p.hour_start) & (minute_of_day < p.hour_end);

        let mut deny_mask = 0u32;
        deny_mask = deny_mask | bit(revoked, 0);
        deny_mask = deny_mask | bit(!member8(p.tools, p.tools_count, tool_id), 1);
        deny_mask = deny_mask | bit(is_solana & !solana_valid, 2);
        deny_mask = deny_mask | bit(p.counterparties_present & !has_counterparty, 3);
        deny_mask = deny_mask
            | bit(
                p.counterparties_present
                    & has_counterparty
                    & !member16(p.counterparties, p.counterparties_count, counterparty_id),
                4,
            );
        deny_mask = deny_mask
            | bit(solana_valid & (!p.clusters_present | !member4(p.clusters, p.clusters_count, cluster_id)), 5);
        deny_mask = deny_mask
            | bit(solana_valid & (!p.programs_present | !member8(p.programs, p.programs_count, program_id)), 6);
        deny_mask = deny_mask
            | bit(solana_valid & (!p.mints_present | !member8(p.mints, p.mints_count, mint_id)), 7);
        deny_mask = deny_mask | bit(solana_valid & non_positive, 8);
        deny_mask = deny_mask | bit(p.drawdown_present & (drawdown_from_peak >= p.drawdown_halt), 9);
        deny_mask = deny_mask | bit(p.max_calls_present & (calls_in_window >= p.max_calls), 10);
        deny_mask = deny_mask
            | bit(
                p.max_per_action_present
                    & has_amount
                    & !amount_at_most(amount_negative, amount_magnitude, p.max_per_action),
                11,
            );
        deny_mask = deny_mask | bit(cap_gate & !cap_found, 12);
        deny_mask = deny_mask
            | bit(cap_gate & cap_found & !amount_at_most(amount_negative, amount_magnitude, cap), 13);
        deny_mask = deny_mask
            | bit(
                p.max_per_window_present
                    & has_amount
                    & !window_at_most(amount_negative, amount_magnitude, spent_in_window, p.max_per_window),
                14,
            );
        deny_mask = deny_mask | bit(day_fails, 15);
        deny_mask = deny_mask | bit(p.hours_present & !in_hours & !day_fails, 16);

        let denied = deny_mask != 0;
        let escalates = !denied
            & p.escalate_present
            & has_amount
            & !amount_negative
            & (amount_magnitude >= p.escalate_above);

        let verdict: u8 = if denied {
            1u8
        } else if escalates {
            2u8
        } else {
            0u8
        };
        let fired = deny_mask | bit(escalates, 17);
        let mask = if disclose_rules { fired } else { 0u32 };

        (verdict.reveal(), mask.reveal())
    }
}
