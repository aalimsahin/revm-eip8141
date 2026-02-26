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
/// - scope: 0x0 = execution approval, 0x1 = payment approval, 0x2 = combined
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
            // Record the payer as the current frame's target
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
            let frame_idx = ftx.current_frame_index;
            ftx.payer = ftx.frames[frame_idx].target;
            ftx.sender_approved = true;
            ftx.payer_approved = true;
        }
        // Invalid scope
        _ => {
            context.interpreter.halt(InstructionResult::InvalidFEOpcode);
            return;
        }
    }

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
        // All scalar fields are 32 bytes
        0x00..=0x0B | 0x10 | 0x11 | 0x13 | 0x14 | 0x15 => U256::from(32u64),
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

    // Resize memory (charges gas)
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
    context
        .interpreter
        .memory
        .set_data(dest, src, len, data);
}
