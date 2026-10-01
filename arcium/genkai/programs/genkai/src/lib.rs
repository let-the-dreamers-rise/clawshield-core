//! GENKAI on-chain program: confidential policy registry and MPC-attested decisions.
//!
//! Lifecycle of a policy:
//!
//!   create_policy      registers the policy id, its salted commitment and the one-time x25519
//!                      key and nonce the ciphertext was encrypted under
//!   stage_ciphertexts  appends encrypted policy fields in order, in transaction-sized chunks
//!   activate_policy    freezes the record once every field is present; it is immutable after
//!   revoke_policy      stops all future evaluation against it
//!
//! Each decision:
//!
//!   evaluate                  authority-only. Records the plaintext request fields in a new
//!                             DecisionRecord and queues evaluate_policy against the ciphertext
//!   evaluate_policy_callback  runs only once the cluster's signature over the output verifies,
//!                             and writes the revealed verdict and rule mask
//!
//! A DecisionRecord is the on-chain attestation: written only by a callback whose output the
//! cluster signed, for exactly the request fields stored alongside it, against a policy whose
//! commitment is fixed in the PolicyRecord it points to.
//!
//! Evaluation is restricted to the policy's authority on purpose. An open evaluator would be an
//! oracle: anyone could binary-search amounts against it and recover every limit the policy
//! exists to keep secret.

use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

const COMP_DEF_OFFSET_EVALUATE_POLICY: u32 = comp_def_offset("evaluate_policy");

/// Number of encrypted scalars in a SealedPolicy; POLICY_FIELD_COUNT in src/mxe/encoding.ts.
pub const POLICY_FIELDS: usize = 87;
/// Bytes of one Arcium ciphertext.
pub const CIPHERTEXT_BYTES: usize = 32;
/// Fields per stage_ciphertexts call, sized to fit one transaction with room for accounts.
pub const MAX_STAGE_CHUNK: usize = 24;
/// Byte offset of PolicyRecord.ciphertexts in the account, discriminator included. Passed to
/// Arcium so the cluster reads the ciphertext straight from the account.
pub const CIPHERTEXT_OFFSET: u32 = 160;

pub const POLICY_SEED: &[u8] = b"policy";
pub const DECISION_SEED: &[u8] = b"decision";

pub const STATUS_STAGING: u8 = 0;
pub const STATUS_ACTIVE: u8 = 1;
pub const STATUS_REVOKED: u8 = 2;

pub const DECISION_PENDING: u8 = 0;
pub const DECISION_DECIDED: u8 = 1;

declare_id!("AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk");

#[arcium_program]
pub mod genkai {
    use super::*;

    pub fn init_evaluate_policy_comp_def(ctx: Context<InitEvaluatePolicyCompDef>) -> Result<()> {
        init_computation_def(ctx.accounts, None)?;
        Ok(())
    }

    pub fn create_policy(
        ctx: Context<CreatePolicy>,
        policy_id: [u8; 32],
        commitment: [u8; 32],
        encryption_pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        let mut record = ctx.accounts.policy.load_init()?;
        record.authority = ctx.accounts.authority.key();
        record.policy_id = policy_id;
        record.commitment = commitment;
        record.encryption_pubkey = encryption_pubkey;
        record.nonce = nonce.to_le_bytes();
        record.status = STATUS_STAGING;
        record.bump = ctx.bumps.policy;
        record.staged_count = 0;
        emit!(PolicyCreated { policy: ctx.accounts.policy.key(), authority: record.authority, policy_id, commitment });
        Ok(())
    }

    /// Append ciphertexts. In order only, so a partially staged policy can never contain a
    /// field written out of sequence, and a retry of the same chunk is rejected, not doubled.
    pub fn stage_ciphertexts(ctx: Context<StagePolicy>, start: u8, ciphertexts: Vec<[u8; 32]>) -> Result<()> {
        let mut record = ctx.accounts.policy.load_mut()?;
        require!(record.status == STATUS_STAGING, GenkaiError::PolicyNotStaging);
        require!(!ciphertexts.is_empty() && ciphertexts.len() <= MAX_STAGE_CHUNK, GenkaiError::BadChunk);
        require!(start == record.staged_count, GenkaiError::OutOfOrderChunk);
        let end = start as usize + ciphertexts.len();
        require!(end <= POLICY_FIELDS, GenkaiError::BadChunk);

        for (i, ct) in ciphertexts.iter().enumerate() {
            record.ciphertexts[start as usize + i] = *ct;
        }
        record.staged_count = end as u8;
        Ok(())
    }

    pub fn activate_policy(ctx: Context<StagePolicy>) -> Result<()> {
        let mut record = ctx.accounts.policy.load_mut()?;
        require!(record.status == STATUS_STAGING, GenkaiError::PolicyNotStaging);
        require!(record.staged_count as usize == POLICY_FIELDS, GenkaiError::PolicyIncomplete);
        record.status = STATUS_ACTIVE;
        emit!(PolicyActivated { policy: ctx.accounts.policy.key(), commitment: record.commitment });
        Ok(())
    }

    pub fn revoke_policy(ctx: Context<StagePolicy>) -> Result<()> {
        let mut record = ctx.accounts.policy.load_mut()?;
        require!(record.status != STATUS_REVOKED, GenkaiError::PolicyRevoked);
        record.status = STATUS_REVOKED;
        emit!(PolicyRevoked { policy: ctx.accounts.policy.key() });
        Ok(())
    }

    pub fn evaluate(ctx: Context<Evaluate>, computation_offset: u64, request: RequestFields) -> Result<()> {
        let (pubkey, nonce) = {
            let record = ctx.accounts.policy.load()?;
            require!(record.status == STATUS_ACTIVE, GenkaiError::PolicyNotActive);
            (record.encryption_pubkey, u128::from_le_bytes(record.nonce))
        };

        let decision = &mut ctx.accounts.decision;
        decision.policy = ctx.accounts.policy.key();
        decision.computation_offset = computation_offset;
        decision.request = request.clone();
        decision.status = DECISION_PENDING;
        decision.verdict = 0;
        decision.mask = 0;
        decision.requested_slot = Clock::get()?.slot;
        decision.decided_slot = 0;
        decision.bump = ctx.bumps.decision;

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            .account(ctx.accounts.policy.key(), CIPHERTEXT_OFFSET, (POLICY_FIELDS * CIPHERTEXT_BYTES) as u32)
            .plaintext_u128(request.tool_id)
            .plaintext_bool(request.has_counterparty)
            .plaintext_u128(request.counterparty_id)
            .plaintext_bool(request.has_amount)
            .plaintext_bool(request.amount_negative)
            .plaintext_u64(request.amount_magnitude)
            .plaintext_bool(request.is_solana)
            .plaintext_bool(request.solana_valid)
            .plaintext_u128(request.cluster_id)
            .plaintext_u128(request.program_id)
            .plaintext_u128(request.mint_id)
            .plaintext_u16(request.minute_of_day)
            .plaintext_u8(request.day_of_week)
            .plaintext_bool(request.revoked)
            .plaintext_u64(request.spent_in_window)
            .plaintext_u64(request.calls_in_window)
            .plaintext_u64(request.drawdown_from_peak)
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![EvaluatePolicyCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount { pubkey: ctx.accounts.decision.key(), is_writable: true }],
            )?],
            1,
            0,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "evaluate_policy")]
    pub fn evaluate_policy_callback(
        ctx: Context<EvaluatePolicyCallback>,
        output: SignedComputationOutputs<EvaluatePolicyOutput>,
    ) -> Result<()> {
        // The output must belong to this decision's own computation. verify_output proves the
        // cluster signed an output for the computation account passed in; without this check a
        // signed allow from one computation could be written into another, still-pending
        // decision whose request the policy would have denied.
        let expected = derive_comp_pda!(ctx.accounts.decision.computation_offset, ctx.accounts.mxe_account);
        require_keys_eq!(ctx.accounts.computation_account.key(), expected, GenkaiError::ComputationMismatch);

        let EvaluatePolicyOutput { field_0: revealed } = output
            .verify_output(&ctx.accounts.cluster_account, &ctx.accounts.computation_account)
            .map_err(|_| GenkaiError::AbortedComputation)?;

        let decision = &mut ctx.accounts.decision;
        require!(decision.status == DECISION_PENDING, GenkaiError::DecisionAlreadyRecorded);
        decision.verdict = revealed.field_0;
        decision.mask = revealed.field_1;
        decision.status = DECISION_DECIDED;
        decision.decided_slot = Clock::get()?.slot;

        emit!(DecisionRecorded {
            decision: decision.key(),
            policy: decision.policy,
            computation_offset: decision.computation_offset,
            verdict: decision.verdict,
            mask: decision.mask,
        });
        Ok(())
    }
}

/// Fixed-layout policy record. zero_copy because the ciphertext alone is 2784 bytes, more than
/// a BPF stack frame can hold if the account were deserialized onto it.
#[account(zero_copy)]
#[repr(C)]
pub struct PolicyRecord {
    pub authority: Pubkey,
    pub policy_id: [u8; 32],
    /// Salted commitment to the plaintext policy; sealedCommitment() in src/policy/sealed.ts.
    pub commitment: [u8; 32],
    /// One-time x25519 key the ciphertext was encrypted under. Public by construction.
    pub encryption_pubkey: [u8; 32],
    /// u128 little endian. Bytes rather than u128 so the struct has no alignment padding.
    pub nonce: [u8; 16],
    pub status: u8,
    pub bump: u8,
    pub staged_count: u8,
    pub _reserved: [u8; 5],
    pub ciphertexts: [[u8; 32]; POLICY_FIELDS],
}

const _: () = assert!(8 + core::mem::offset_of!(PolicyRecord, ciphertexts) == CIPHERTEXT_OFFSET as usize);

/// The request fields the circuit evaluated, stored in the clear so anyone can check them
/// against a receipt. Field order and meaning match EncodedRequest in src/mxe/encoding.ts.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, InitSpace)]
pub struct RequestFields {
    pub tool_id: u128,
    pub has_counterparty: bool,
    pub counterparty_id: u128,
    pub has_amount: bool,
    pub amount_negative: bool,
    pub amount_magnitude: u64,
    pub is_solana: bool,
    pub solana_valid: bool,
    pub cluster_id: u128,
    pub program_id: u128,
    pub mint_id: u128,
    pub minute_of_day: u16,
    pub day_of_week: u8,
    pub revoked: bool,
    pub spent_in_window: u64,
    pub calls_in_window: u64,
    pub drawdown_from_peak: u64,
}

#[account]
#[derive(InitSpace)]
pub struct DecisionRecord {
    pub policy: Pubkey,
    pub computation_offset: u64,
    pub request: RequestFields,
    pub status: u8,
    /// 0 allow, 1 deny, 2 escalate.
    pub verdict: u8,
    /// Bit i is RULE_ORDER[i] in src/mxe/circuit.ts.
    pub mask: u32,
    pub requested_slot: u64,
    pub decided_slot: u64,
    pub bump: u8,
}

#[derive(Accounts)]
#[instruction(policy_id: [u8; 32])]
pub struct CreatePolicy<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + core::mem::size_of::<PolicyRecord>(),
        seeds = [POLICY_SEED, authority.key().as_ref(), policy_id.as_ref()],
        bump,
    )]
    pub policy: AccountLoader<'info, PolicyRecord>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StagePolicy<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority @ GenkaiError::NotAuthority)]
    pub policy: AccountLoader<'info, PolicyRecord>,
}

#[queue_computation_accounts("evaluate_policy", authority)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct Evaluate<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(has_one = authority @ GenkaiError::NotAuthority)]
    pub policy: AccountLoader<'info, PolicyRecord>,
    #[account(
        init,
        payer = authority,
        space = 8 + DecisionRecord::INIT_SPACE,
        seeds = [DECISION_SEED, policy.key().as_ref(), &computation_offset.to_le_bytes()],
        bump,
    )]
    pub decision: Account<'info, DecisionRecord>,
    #[account(
        init_if_needed,
        space = 9,
        payer = authority,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_EVALUATE_POLICY))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

/// Accounts are boxed: the callback also verifies a BLS signature, and with the cluster, MXE and
/// decision accounts deserialized onto the stack the SBF runtime runs out of frame space
/// ("exceeded max BPF to BPF call depth").
#[callback_accounts("evaluate_policy")]
#[derive(Accounts)]
pub struct EvaluatePolicyCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_EVALUATE_POLICY))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: address is validated by the Arcium program; verify_output reads slot data from it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub decision: Box<Account<'info, DecisionRecord>>,
}

#[init_computation_definition_accounts("evaluate_policy", payer)]
#[derive(Accounts)]
pub struct InitEvaluatePolicyCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program. Not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct PolicyCreated {
    pub policy: Pubkey,
    pub authority: Pubkey,
    pub policy_id: [u8; 32],
    pub commitment: [u8; 32],
}

#[event]
pub struct PolicyActivated {
    pub policy: Pubkey,
    pub commitment: [u8; 32],
}

#[event]
pub struct PolicyRevoked {
    pub policy: Pubkey,
}

#[event]
pub struct DecisionRecorded {
    pub decision: Pubkey,
    pub policy: Pubkey,
    pub computation_offset: u64,
    pub verdict: u8,
    pub mask: u32,
}

#[error_code]
pub enum GenkaiError {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Only the policy authority may do this")]
    NotAuthority,
    #[msg("The policy is not accepting ciphertext")]
    PolicyNotStaging,
    #[msg("The policy is not active")]
    PolicyNotActive,
    #[msg("The policy has been revoked")]
    PolicyRevoked,
    #[msg("Not every policy field has been staged")]
    PolicyIncomplete,
    #[msg("A chunk must be non-empty, within the chunk limit and inside the policy")]
    BadChunk,
    #[msg("Chunks must be staged in order")]
    OutOfOrderChunk,
    #[msg("This decision has already been recorded")]
    DecisionAlreadyRecorded,
    #[msg("The output belongs to a different computation than this decision")]
    ComputationMismatch,
}
