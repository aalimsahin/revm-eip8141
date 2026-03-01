//! EIP-8141 Frame Transaction opcode implementations.
//!
//! Provides APPROVE (0xAA), TXPARAMLOAD (0xB0), TXPARAMSIZE (0xB1),
//! and TXPARAMCOPY (0xB2) opcode handlers.

use crate::{
    interpreter_types::{InterpreterTypes, LoopControl, MemoryTr, StackTr},
    InstructionContext, InstructionResult, InterpreterAction,
};
use context_interface::{ContextTr, Host};
use primitives::{Address, Bytes, B256, U256};

// ─── FrameTxContext ─────────────────────────────────────────────────────────

/// Transaction-scoped state for EIP-8141 frame transactions.
///
/// This struct is threaded through the EVM via the external context (`chain`)
/// and provides the frame execution state that opcodes need to read and write.
#[derive(Debug, Clone, Default)]
pub struct FrameTxContext {
    /// Whether this EVM invocation is executing an EIP-8141 frame transaction.
    /// When false, all EIP-8141 opcodes behave as INVALID.
    pub active: bool,

    /// Set to true when a VERIFY frame calls APPROVE with scope 0x0 or 0x2.
    pub sender_approved: bool,

    /// Set to true when APPROVE is called with scope 0x1 or 0x2.
    pub payer_approved: bool,

    /// The explicit sender of the frame transaction.
    pub sender: Address,

    /// The payer address (set when payer_approved becomes true).
    ///
    /// Semantics:
    /// - APPROVE scope 0x1: payer = current frame target (sponsor pattern)
    /// - APPROVE scope 0x2: payer = sender
    pub payer: Address,

    /// Transaction type byte (0x06).
    pub tx_type: u8,

    /// Transaction nonce.
    pub nonce: u64,

    /// max_priority_fee_per_gas
    pub max_priority_fee_per_gas: u128,

    /// max_fee_per_gas
    pub max_fee_per_gas: u128,

    /// max_fee_per_blob_gas
    pub max_fee_per_blob_gas: u128,

    /// Maximum cost of the transaction.
    pub max_cost: U256,

    /// Blob versioned hashes.
    pub blob_versioned_hashes: Vec<B256>,

    /// Precomputed signature hash (keccak256 of tx with VERIFY data zeroed).
    pub sig_hash: B256,

    /// Total number of frames in the transaction.
    pub frame_count: usize,

    /// Index of the currently executing frame.
    pub current_frame_index: usize,

    /// Frame metadata for all frames.
    pub frames: Vec<FrameInfo>,

    /// Set to `true` when APPROVE is successfully called during the current frame.
    /// Reset to `false` before each VERIFY frame execution by the executor.
    /// Used instead of the fragile approval-changed heuristic.
    pub approve_called_current_frame: bool,
}

/// Metadata for a single frame within a frame transaction.
#[derive(Debug, Clone, Default)]
pub struct FrameInfo {
    /// Frame mode: 0=DEFAULT, 1=VERIFY, 2=SENDER
    pub mode: u8,
    /// Frame target address.
    pub target: Address,
    /// Frame gas limit.
    pub gas_limit: u64,
    /// Frame calldata.
    pub data: Bytes,
    /// Execution status: None=not yet executed, Some(true)=success, Some(false)=fail
    pub status: Option<bool>,
}

// ─── Trait for accessing FrameTxContext from opcode handlers ─────────────────

/// Trait that allows opcode handlers to access the EIP-8141 frame transaction context.
///
/// This must be implemented on the Host type (typically `Context<..., FrameTxContext>`)
/// to enable EIP-8141 opcodes.
///
/// A blanket implementation is provided for any type implementing `ContextTr` with
/// `Chain = FrameTxContext`, so `Context<..., FrameTxContext, ...>` gets this for free.
pub trait FrameTxHost {
    /// Returns a reference to the frame transaction context.
    fn frame_tx_context(&self) -> &FrameTxContext;
    /// Returns a mutable reference to the frame transaction context.
    fn frame_tx_context_mut(&mut self) -> &mut FrameTxContext;
}

/// Blanket implementation: any revm `Context` with `Chain = FrameTxContext`
/// automatically implements `FrameTxHost`.
impl<T> FrameTxHost for T
where
    T: ContextTr<Chain = FrameTxContext>,
{
    fn frame_tx_context(&self) -> &FrameTxContext {
        self.chain()
    }
    fn frame_tx_context_mut(&mut self) -> &mut FrameTxContext {
        self.chain_mut()
    }
}

// ─── APPROVE opcode (0xAA) ──────────────────────────────────────────────────

/// APPROVE opcode (0xAA) — EIP-8141 frame transaction approval.
///
/// Stack inputs (top first): [offset, length, scope]
/// - offset: memory offset for return data
/// - length: byte length of return data
/// - scope:
///   - 0x0 = execution approval (sender only)
///   - 0x1 = payment approval (payer = current frame target)
///   - 0x2 = combined execution+payment approval (payer = sender)
///
/// Behaves like RETURN (terminates execution) but also updates transaction-scoped
/// approval state (sender_approved / payer_approved).
pub fn approve<WIRE: InterpreterTypes, H: Host + FrameTxHost + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    // Check that we're in an active frame transaction
    if !context.host.frame_tx_context().active {
        context.interpreter.halt(InstructionResult::OpcodeNotFound);
        return;
    }

    // APPROVE is only valid inside a VERIFY frame (mode == 1).
    {
        let ftx = context.host.frame_tx_context();
        let idx = ftx.current_frame_index;
        if idx >= ftx.frames.len() || ftx.frames[idx].mode != 1 {
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    }

    popn!([offset, len, scope], context.interpreter);

    let scope_val = as_usize_saturated!(scope);

    // Get return data from memory (like RETURN)
    let len_usize = as_usize_or_fail!(context.interpreter, len);
    let mut output = Bytes::default();
    if len_usize != 0 {
        let offset_usize = as_usize_or_fail!(context.interpreter, offset);
        if !context
            .interpreter
            .resize_memory(context.host.gas_params(), offset_usize, len_usize)
        {
            return;
        }
        output = context
            .interpreter
            .memory
            .slice_len(offset_usize, len_usize)
            .to_vec()
            .into();
    }

    let ftx = context.host.frame_tx_context_mut();

    match scope_val {
        // Scope 0x0: Execution approval (sender only)
        0x0 => {
            if ftx.sender_approved {
                // Already approved — revert
                context.interpreter.halt(InstructionResult::Revert);
                return;
            }
            ftx.sender_approved = true;
        }
        // Scope 0x1: Payment approval
        0x1 => {
            if !ftx.sender_approved {
                // Sender must be approved first
                context.interpreter.halt(InstructionResult::Revert);
                return;
            }
            if ftx.payer_approved {
                // Already approved — revert
                context.interpreter.halt(InstructionResult::Revert);
                return;
            }
            // Payment approval delegates gas payment to the current frame target.
            let frame_idx = ftx.current_frame_index;
            ftx.payer = ftx.frames[frame_idx].target;
            ftx.payer_approved = true;
        }
        // Scope 0x2: Combined execution + payment approval
        0x2 => {
            if ftx.sender_approved || ftx.payer_approved {
                // Cannot use combined if either is already set
                context.interpreter.halt(InstructionResult::Revert);
                return;
            }
            // Combined approval means sender and payer are the transaction sender.
            ftx.payer = ftx.sender;
            ftx.sender_approved = true;
            ftx.payer_approved = true;
        }
        // Invalid scope
        _ => {
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    }

    // Mark that APPROVE was called in this frame (for executor to check).
    ftx.approve_called_current_frame = true;

    // Terminate like RETURN — set the return action
    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::new_return(
            InstructionResult::Return,
            output,
            context.interpreter.gas,
        ));
}

// ─── TXPARAMLOAD opcode (0xB0) ─────────────────────────────────────────────

/// TXPARAMLOAD opcode (0xB0) — Load a transaction parameter as a 32-byte value.
///
/// Stack inputs (top first): [in1, in2]
/// Stack output: [value]
///
/// Parameter ID space:
///   0x00-0x09: Transaction-level scalar parameters
///   0x0A-0x0F: Reserved for future tx-level parameters
///   0x10:      Current frame index (scalar)
///   0x11-0x15: Frame-indexed parameters (require index argument)
///
/// Parameter table:
/// - (0x00, 0): tx type (0x06)
/// - (0x01, 0): nonce
/// - (0x02, 0): sender (padded to 32 bytes)
/// - (0x03, 0): max_priority_fee_per_gas
/// - (0x04, 0): max_fee_per_gas
/// - (0x05, 0): max_fee_per_blob_gas
/// - (0x06, 0): max cost
/// - (0x07, 0): len(blob_versioned_hashes)
/// - (0x08, 0): signature hash
/// - (0x09, 0): len(frames)
/// - (0x10, 0): current frame index
/// - (0x11, i): frames[i].target
/// - (0x12, i): frames[i].data (dynamic — use TXPARAMSIZE/TXPARAMCOPY)
/// - (0x13, i): frames[i].gas_limit
/// - (0x14, i): frames[i].mode
/// - (0x15, i): frames[i].status (only past frames)
pub fn txparamload<WIRE: InterpreterTypes, H: Host + FrameTxHost + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.host.frame_tx_context().active {
        context.interpreter.halt(InstructionResult::OpcodeNotFound);
        return;
    }

    popn!([in1, in2], context.interpreter);

    let param_id = as_usize_saturated!(in1);
    let index = as_usize_saturated!(in2);
    let ftx = context.host.frame_tx_context();

    let value: U256 = match param_id {
        0x00 => {
            // tx type
            U256::from(ftx.tx_type)
        }
        0x01 => {
            // nonce
            U256::from(ftx.nonce)
        }
        0x02 => {
            // sender (address padded to 32 bytes)
            let mut word = [0u8; 32];
            word[12..32].copy_from_slice(ftx.sender.as_slice());
            U256::from_be_bytes(word)
        }
        0x03 => {
            // max_priority_fee_per_gas
            U256::from(ftx.max_priority_fee_per_gas)
        }
        0x04 => {
            // max_fee_per_gas
            U256::from(ftx.max_fee_per_gas)
        }
        0x05 => {
            // max_fee_per_blob_gas
            U256::from(ftx.max_fee_per_blob_gas)
        }
        0x06 => {
            // max cost
            ftx.max_cost
        }
        0x07 => {
            // len(blob_versioned_hashes)
            U256::from(ftx.blob_versioned_hashes.len())
        }
        0x08 => {
            // signature hash
            U256::from_be_bytes(ftx.sig_hash.0)
        }
        0x09 => {
            // len(frames)
            U256::from(ftx.frame_count)
        }
        0x10 => {
            // current frame index
            U256::from(ftx.current_frame_index)
        }
        0x11 => {
            // frames[in2].target
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            let mut word = [0u8; 32];
            word[12..32].copy_from_slice(ftx.frames[index].target.as_slice());
            U256::from_be_bytes(word)
        }
        0x12 => {
            // frames[in2].data — for TXPARAMLOAD this returns the first 32 bytes
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            // VERIFY frame data is opaque — return empty
            if ftx.frames[index].mode == 1 {
                U256::ZERO
            } else {
                let data = &ftx.frames[index].data;
                let mut word = [0u8; 32];
                let copy_len = data.len().min(32);
                word[..copy_len].copy_from_slice(&data[..copy_len]);
                U256::from_be_bytes(word)
            }
        }
        0x13 => {
            // frames[in2].gas_limit
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            U256::from(ftx.frames[index].gas_limit)
        }
        0x14 => {
            // frames[in2].mode
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            U256::from(ftx.frames[index].mode)
        }
        0x15 => {
            // frames[in2].status — only past frames allowed
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            if index >= ftx.current_frame_index {
                // Cannot read status of current or future frame
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            match ftx.frames[index].status {
                Some(true) => U256::from(1u64),
                Some(false) => U256::ZERO,
                None => U256::ZERO,
            }
        }
        _ => {
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    };

    push!(context.interpreter, value);
}

// ─── TXPARAMSIZE opcode (0xB1) ─────────────────────────────────────────────

/// TXPARAMSIZE opcode (0xB1) — Get the byte size of a transaction parameter.
///
/// Stack inputs (top first): [in1, in2]
/// Stack output: [size]
///
/// Most parameters return 32. Dynamic fields (like frame data at 0x12) return
/// their actual byte length.
pub fn txparamsize<WIRE: InterpreterTypes, H: Host + FrameTxHost + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.host.frame_tx_context().active {
        context.interpreter.halt(InstructionResult::OpcodeNotFound);
        return;
    }

    popn!([in1, in2], context.interpreter);

    let param_id = as_usize_saturated!(in1);
    let index = as_usize_saturated!(in2);
    let ftx = context.host.frame_tx_context();

    let size: U256 = match param_id {
        // Transaction-level scalar parameters (no index needed)
        0x00..=0x09 | 0x10 => U256::from(32u64),
        // Frame-indexed scalar parameters (require bounds check)
        0x11 | 0x13 | 0x14 => {
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            U256::from(32u64)
        }
        // frames[in2].status — only past frames allowed (consistent with TXPARAMLOAD)
        0x15 => {
            if index >= ftx.frame_count || index >= ftx.current_frame_index {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            U256::from(32u64)
        }
        // Frame data is dynamic
        0x12 => {
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            // VERIFY frame data is opaque — size 0
            if ftx.frames[index].mode == 1 {
                U256::ZERO
            } else {
                U256::from(ftx.frames[index].data.len())
            }
        }
        _ => {
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    };

    push!(context.interpreter, size);
}

// ─── TXPARAMCOPY opcode (0xB2) ─────────────────────────────────────────────

/// TXPARAMCOPY opcode (0xB2) — Copy transaction parameter data to memory.
///
/// Stack inputs (top first): [in1, in2, dest_offset, src_offset, length]
///
/// Copies `length` bytes from parameter field (in1, in2) starting at `src_offset`
/// into memory at `dest_offset`. Charges memory expansion gas.
pub fn txparamcopy<WIRE: InterpreterTypes, H: Host + FrameTxHost + ?Sized>(
    context: InstructionContext<'_, H, WIRE>,
) {
    if !context.host.frame_tx_context().active {
        context.interpreter.halt(InstructionResult::OpcodeNotFound);
        return;
    }

    popn!(
        [in1, in2, dest_offset, src_offset, length],
        context.interpreter
    );

    let param_id = as_usize_saturated!(in1);
    let index = as_usize_saturated!(in2);
    let len = as_usize_or_fail!(context.interpreter, length);

    if len == 0 {
        return;
    }

    let dest = as_usize_or_fail!(context.interpreter, dest_offset);
    let src = as_usize_saturated!(src_offset);

    // Charge per-word copy gas (3 gas per 32-byte word), matching CALLDATACOPY semantics.
    gas!(context.interpreter, context.host.gas_params().copy_cost(len));

    // Resize memory (charges expansion gas)
    if !context
        .interpreter
        .resize_memory(context.host.gas_params(), dest, len)
    {
        return;
    }

    let ftx = context.host.frame_tx_context();

    // Get the source data buffer for the requested parameter
    let data: &[u8] = match param_id {
        0x12 => {
            // Frame data
            if index >= ftx.frame_count {
                context.interpreter.halt(InstructionResult::InvalidFEOpcode);
                return;
            }
            // VERIFY frame data is opaque
            if ftx.frames[index].mode == 1 {
                &[]
            } else {
                &ftx.frames[index].data
            }
        }
        // For scalar fields, serialize to a temporary buffer
        _ => {
            // TXPARAMCOPY is primarily useful for dynamic data (0x12).
            // For scalar fields, use TXPARAMLOAD instead.
            // We still support it by serializing the 32-byte value.
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    };

    // Copy data to memory, zero-padding if src+len exceeds data length
    context.interpreter.memory.set_data(dest, src, len, data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InstructionContext, Interpreter};
    use context_interface::{Host, cfg::GasParams, host::LoadError};
    use primitives::{Address, Bytes, Log, B256, U256};

    // ── Test host that wraps DummyHost + FrameTxContext ──────────────────

    struct TestHost {
        gas_params: GasParams,
        ftx: FrameTxContext,
    }

    impl TestHost {
        fn new(ftx: FrameTxContext) -> Self {
            Self {
                gas_params: GasParams::default(),
                ftx,
            }
        }
    }

    impl Host for TestHost {
        fn basefee(&self) -> U256 { U256::ZERO }
        fn blob_gasprice(&self) -> U256 { U256::ZERO }
        fn gas_limit(&self) -> U256 { U256::ZERO }
        fn gas_params(&self) -> &GasParams { &self.gas_params }
        fn difficulty(&self) -> U256 { U256::ZERO }
        fn prevrandao(&self) -> Option<U256> { None }
        fn block_number(&self) -> U256 { U256::ZERO }
        fn timestamp(&self) -> U256 { U256::ZERO }
        fn beneficiary(&self) -> Address { Address::ZERO }
        fn chain_id(&self) -> U256 { U256::ZERO }
        fn effective_gas_price(&self) -> U256 { U256::ZERO }
        fn caller(&self) -> Address { Address::ZERO }
        fn blob_hash(&self, _number: usize) -> Option<U256> { None }
        fn max_initcode_size(&self) -> usize { 0 }
        fn block_hash(&mut self, _number: u64) -> Option<B256> { None }
        fn selfdestruct(
            &mut self, _address: Address, _target: Address, _skip_cold_load: bool,
        ) -> Result<context_interface::context::StateLoad<context_interface::context::SelfDestructResult>, LoadError> {
            Err(LoadError::DBError)
        }
        fn log(&mut self, _log: Log) {}
        fn tstore(&mut self, _address: Address, _key: primitives::StorageKey, _value: primitives::StorageValue) {}
        fn tload(&mut self, _address: Address, _key: primitives::StorageKey) -> primitives::StorageValue {
            primitives::StorageValue::ZERO
        }
        fn load_account_info_skip_cold_load(
            &mut self, _address: Address, _load_code: bool, _skip_cold_load: bool,
        ) -> Result<context_interface::journaled_state::AccountInfoLoad<'_>, LoadError> {
            Err(LoadError::DBError)
        }
        fn sstore_skip_cold_load(
            &mut self, _address: Address, _key: primitives::StorageKey, _value: primitives::StorageValue, _skip_cold_load: bool,
        ) -> Result<context_interface::context::StateLoad<context_interface::context::SStoreResult>, LoadError> {
            Err(LoadError::DBError)
        }
        fn sload_skip_cold_load(
            &mut self, _address: Address, _key: primitives::StorageKey, _skip_cold_load: bool,
        ) -> Result<context_interface::context::StateLoad<primitives::StorageValue>, LoadError> {
            Err(LoadError::DBError)
        }
    }

    impl FrameTxHost for TestHost {
        fn frame_tx_context(&self) -> &FrameTxContext { &self.ftx }
        fn frame_tx_context_mut(&mut self) -> &mut FrameTxContext { &mut self.ftx }
    }

    // ── Helper to build a FrameTxContext with sensible defaults ──────────

    fn make_ftx() -> FrameTxContext {
        let target_addr = Address::new([0xAA; 20]);
        FrameTxContext {
            active: true,
            sender_approved: false,
            payer_approved: false,
            sender: Address::new([0x11; 20]),
            payer: Address::new([0x11; 20]),
            tx_type: 0x06,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            max_fee_per_blob_gas: 100,
            max_cost: U256::from(999_999u64),
            blob_versioned_hashes: vec![B256::from([0xBB; 32])],
            sig_hash: B256::from([0xCC; 32]),
            frame_count: 3,
            current_frame_index: 1,
            frames: vec![
                FrameInfo {
                    mode: 1, // VERIFY
                    target: target_addr,
                    gas_limit: 100_000,
                    data: Bytes::from_static(&[0x01, 0x02, 0x03]),
                    status: Some(true),
                },
                FrameInfo {
                    mode: 1, // VERIFY (current)
                    target: target_addr,
                    gas_limit: 200_000,
                    data: Bytes::from_static(&[0xAA, 0xBB]),
                    status: None,
                },
                FrameInfo {
                    mode: 2, // SENDER
                    target: Address::new([0x22; 20]),
                    gas_limit: 50_000,
                    data: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
                    status: None,
                },
            ],
            approve_called_current_frame: false,
        }
    }

    /// Helper: get the instruction result (halt status) from the interpreter.
    fn halt_result(interpreter: &mut Interpreter<crate::interpreter::EthInterpreter>) -> Option<InstructionResult> {
        interpreter.bytecode.instruction_result()
    }

    // ── APPROVE tests ───────────────────────────────────────────────────

    #[test]
    fn approve_only_works_in_verify_mode() {
        // APPROVE in a DEFAULT frame (mode=0) should fail.
        let mut ftx = make_ftx();
        ftx.frames[1].mode = 0; // DEFAULT
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();

        // Push: offset=0, length=0, scope=0x00
        push!(interpreter, U256::from(0u64)); // scope
        push!(interpreter, U256::from(0u64)); // length
        push!(interpreter, U256::from(0u64)); // offset

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        approve(ctx);

        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::InvalidFEOpcode));
    }

    #[test]
    fn approve_scope_0x00_sets_sender_approved() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();

        push!(interpreter, U256::from(0u64)); // scope = 0x00 (sender)
        push!(interpreter, U256::from(0u64)); // length
        push!(interpreter, U256::from(0u64)); // offset

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        approve(ctx);

        assert!(host.ftx.sender_approved);
        assert!(!host.ftx.payer_approved);
        assert!(host.ftx.approve_called_current_frame);
    }

    #[test]
    fn approve_scope_0x01_sets_payer_approved() {
        let mut ftx = make_ftx();
        ftx.sender_approved = true; // sender must be approved first
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();

        push!(interpreter, U256::from(1u64)); // scope = 0x01 (payer)
        push!(interpreter, U256::from(0u64)); // length
        push!(interpreter, U256::from(0u64)); // offset

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        approve(ctx);

        assert!(host.ftx.payer_approved);
        // Payer should be set to current frame's target
        assert_eq!(host.ftx.payer, host.ftx.frames[1].target);
    }

    #[test]
    fn approve_scope_0x02_sets_both() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();

        push!(interpreter, U256::from(2u64)); // scope = 0x02 (combined)
        push!(interpreter, U256::from(0u64)); // length
        push!(interpreter, U256::from(0u64)); // offset

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        approve(ctx);

        assert!(host.ftx.sender_approved);
        assert!(host.ftx.payer_approved);
        assert_eq!(host.ftx.payer, host.ftx.sender);
    }

    #[test]
    fn approve_inactive_halts_opcode_not_found() {
        let mut ftx = make_ftx();
        ftx.active = false;
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();

        push!(interpreter, U256::from(0u64));
        push!(interpreter, U256::from(0u64));
        push!(interpreter, U256::from(0u64));

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        approve(ctx);

        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::OpcodeNotFound));
    }

    // ── TXPARAMLOAD tests ───────────────────────────────────────────────

    #[test]
    fn txparamload_tx_type() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);       // in2
        push!(interpreter, U256::from(0x00)); // in1 = tx_type
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(0x06u64));
    }

    #[test]
    fn txparamload_nonce() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x01));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(42u64));
    }

    #[test]
    fn txparamload_sender() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x02));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        let result = interpreter.stack.pop().unwrap();
        let mut expected = [0u8; 32];
        expected[12..32].copy_from_slice(&[0x11; 20]);
        assert_eq!(result, U256::from_be_bytes(expected));
    }

    #[test]
    fn txparamload_max_cost() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x06));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(999_999u64));
    }

    #[test]
    fn txparamload_frame_count() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x09));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(3u64));
    }

    #[test]
    fn txparamload_current_frame_index() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x10));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(1u64));
    }

    #[test]
    fn txparamload_frame_gas_limit() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(2u64)); // frame index 2
        push!(interpreter, U256::from(0x13)); // gas_limit
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(50_000u64));
    }

    #[test]
    fn txparamload_frame_mode() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(2u64)); // frame index 2 (SENDER)
        push!(interpreter, U256::from(0x14)); // mode
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(2u64)); // SENDER = 2
    }

    #[test]
    fn txparamload_oob_frame_index_halts() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(99u64)); // OOB index
        push!(interpreter, U256::from(0x11));  // target
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::InvalidFEOpcode));
    }

    #[test]
    fn txparamload_frame_status_past_frame() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(0u64)); // frame 0 (past, status=Some(true))
        push!(interpreter, U256::from(0x15));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(1u64)); // true
    }

    #[test]
    fn txparamload_frame_status_current_frame_halts() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(1u64)); // current frame (index == current_frame_index)
        push!(interpreter, U256::from(0x15));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::InvalidFEOpcode));
    }

    #[test]
    fn txparamload_inactive_halts() {
        let mut ftx = make_ftx();
        ftx.active = false;
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x00));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamload(ctx);
        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::OpcodeNotFound));
    }

    // ── TXPARAMSIZE tests ───────────────────────────────────────────────

    #[test]
    fn txparamsize_scalar_fields_return_32() {
        for param_id in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10] {
            let mut host = TestHost::new(make_ftx());
            let mut interpreter = Interpreter::default();
            push!(interpreter, U256::ZERO);
            push!(interpreter, U256::from(param_id));
            let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
            txparamsize(ctx);
            assert_eq!(
                interpreter.stack.pop().unwrap(),
                U256::from(32u64),
                "param_id 0x{param_id:02x} should return size 32"
            );
        }
    }

    #[test]
    fn txparamsize_frame_indexed_scalars_check_bounds() {
        for param_id in [0x11u64, 0x13, 0x14] {
            // Valid index
            let mut host = TestHost::new(make_ftx());
            let mut interpreter = Interpreter::default();
            push!(interpreter, U256::from(0u64));
            push!(interpreter, U256::from(param_id));
            let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
            txparamsize(ctx);
            assert_eq!(
                interpreter.stack.pop().unwrap(),
                U256::from(32u64),
                "param_id 0x{param_id:02x} with valid index should return 32"
            );

            // OOB index
            let mut host = TestHost::new(make_ftx());
            let mut interpreter = Interpreter::default();
            push!(interpreter, U256::from(99u64));
            push!(interpreter, U256::from(param_id));
            let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
            txparamsize(ctx);
            assert_eq!(
                halt_result(&mut interpreter),
                Some(InstructionResult::InvalidFEOpcode),
                "param_id 0x{param_id:02x} with OOB index should halt"
            );
        }
    }

    #[test]
    fn txparamsize_dynamic_data() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        // Frame 2 (SENDER mode) has 4 bytes of data
        push!(interpreter, U256::from(2u64));
        push!(interpreter, U256::from(0x12));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamsize(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::from(4u64));
    }

    #[test]
    fn txparamsize_verify_data_opaque_zero() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        // Frame 0 (VERIFY mode) data is opaque — size 0
        push!(interpreter, U256::from(0u64));
        push!(interpreter, U256::from(0x12));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamsize(ctx);
        assert_eq!(interpreter.stack.pop().unwrap(), U256::ZERO);
    }

    #[test]
    fn txparamsize_inactive_halts() {
        let mut ftx = make_ftx();
        ftx.active = false;
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(0x00));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamsize(ctx);
        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::OpcodeNotFound));
    }

    // ── TXPARAMCOPY tests ───────────────────────────────────────────────

    #[test]
    fn txparamcopy_copies_frame_data() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        // Copy frame 2's data (0xDEADBEEF, 4 bytes) to memory offset 0
        push!(interpreter, U256::from(4u64));  // length
        push!(interpreter, U256::ZERO);         // src_offset
        push!(interpreter, U256::ZERO);         // dest_offset
        push!(interpreter, U256::from(2u64));  // in2 = frame index
        push!(interpreter, U256::from(0x12u64)); // in1 = data param
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert!(halt_result(&mut interpreter).is_none(), "should not halt");
        let mem = interpreter.memory.slice_len(0, 4);
        assert_eq!(&*mem, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn txparamcopy_zero_pads() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        // Copy 8 bytes from frame 2 data (only 4 bytes) — should zero-pad
        push!(interpreter, U256::from(8u64));  // length (> data len)
        push!(interpreter, U256::ZERO);         // src_offset
        push!(interpreter, U256::ZERO);         // dest_offset
        push!(interpreter, U256::from(2u64));  // frame index
        push!(interpreter, U256::from(0x12u64)); // data param
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert!(halt_result(&mut interpreter).is_none(), "should not halt");
        let mem = interpreter.memory.slice_len(0, 8);
        assert_eq!(&*mem, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn txparamcopy_zero_length_noop() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::ZERO);         // length = 0
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(2u64));
        push!(interpreter, U256::from(0x12u64));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert!(halt_result(&mut interpreter).is_none(), "zero-length copy should not halt");
    }

    #[test]
    fn txparamcopy_inactive_halts() {
        let mut ftx = make_ftx();
        ftx.active = false;
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();
        push!(interpreter, U256::from(4u64));
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(2u64));
        push!(interpreter, U256::from(0x12u64));
        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert_eq!(halt_result(&mut interpreter), Some(InstructionResult::OpcodeNotFound));
    }

    // ── TXPARAMCOPY gas tests ─────────────────────────────────────────

    #[test]
    fn txparamcopy_charges_copy_gas() {
        let mut host = TestHost::new(make_ftx());
        let mut interpreter = Interpreter::default();
        let gas_before = interpreter.gas.remaining();

        // Copy 4 bytes of frame data = 1 word → copy cost = 3 gas
        push!(interpreter, U256::from(4u64));     // length
        push!(interpreter, U256::ZERO);            // src_offset
        push!(interpreter, U256::ZERO);            // dest_offset
        push!(interpreter, U256::from(2u64));     // frame index
        push!(interpreter, U256::from(0x12u64));  // data param

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert!(halt_result(&mut interpreter).is_none(), "should not halt");

        let gas_after = interpreter.gas.remaining();
        let gas_spent = gas_before - gas_after;
        // Must include copy cost (3 gas for 1 word) + memory expansion gas.
        // Copy cost alone = 3 gas per 32-byte word, ceil(4/32) = 1 word → 3 gas.
        assert!(
            gas_spent >= 3,
            "expected at least 3 gas for copy cost, spent {gas_spent}"
        );
    }

    #[test]
    fn txparamcopy_copy_gas_scales_with_words() {
        // 33 bytes → 2 words → 6 gas copy cost
        let mut ftx = make_ftx();
        // Give frame 2 enough data (33 bytes)
        ftx.frames[2].data = Bytes::from(vec![0xAB; 33]);
        let mut host = TestHost::new(ftx);
        let mut interpreter = Interpreter::default();
        let gas_before = interpreter.gas.remaining();

        push!(interpreter, U256::from(33u64));    // length = 33 → 2 words
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(2u64));
        push!(interpreter, U256::from(0x12u64));

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        assert!(halt_result(&mut interpreter).is_none(), "should not halt");

        let gas_spent = gas_before - interpreter.gas.remaining();
        // 2 words × 3 gas = 6 gas minimum (+ memory expansion)
        assert!(
            gas_spent >= 6,
            "expected at least 6 gas for 2-word copy, spent {gas_spent}"
        );
    }

    #[test]
    fn txparamcopy_oog_on_insufficient_gas_for_copy() {
        use crate::interpreter::{EthInterpreter, SharedMemory, ExtBytecode, InputsImpl};
        use primitives::hardfork::SpecId;

        let mut host = TestHost::new(make_ftx());
        // Create interpreter with only 2 gas — not enough for 3-gas copy cost
        let mut interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::default(),
            InputsImpl::default(),
            false,
            SpecId::default(),
            2, // only 2 gas
        );

        push!(interpreter, U256::from(4u64));     // length (1 word → 3 gas copy)
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::ZERO);
        push!(interpreter, U256::from(2u64));
        push!(interpreter, U256::from(0x12u64));

        let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
        txparamcopy(ctx);
        // Should OOG because 2 gas < 3 gas copy cost
        assert_eq!(
            halt_result(&mut interpreter),
            Some(InstructionResult::OutOfGas),
            "should halt with OOG when gas < copy cost"
        );
    }

    // ── ET4: Reserved param IDs 0x0A-0x0F return InvalidFEOpcode ────────

    #[test]
    fn reserved_param_ids_halt_txparamload() {
        for param_id in 0x0Au64..=0x0F {
            let mut host = TestHost::new(make_ftx());
            let mut interpreter = Interpreter::default();
            push!(interpreter, U256::ZERO);
            push!(interpreter, U256::from(param_id));
            let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
            txparamload(ctx);
            assert_eq!(
                halt_result(&mut interpreter),
                Some(InstructionResult::InvalidFEOpcode),
                "TXPARAMLOAD with reserved param_id 0x{param_id:02x} should halt"
            );
        }
    }

    #[test]
    fn reserved_param_ids_halt_txparamsize() {
        for param_id in 0x0Au64..=0x0F {
            let mut host = TestHost::new(make_ftx());
            let mut interpreter = Interpreter::default();
            push!(interpreter, U256::ZERO);
            push!(interpreter, U256::from(param_id));
            let ctx = InstructionContext { host: &mut host, interpreter: &mut interpreter };
            txparamsize(ctx);
            assert_eq!(
                halt_result(&mut interpreter),
                Some(InstructionResult::InvalidFEOpcode),
                "TXPARAMSIZE with reserved param_id 0x{param_id:02x} should halt"
            );
        }
    }
}
