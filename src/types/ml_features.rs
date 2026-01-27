//! ML-ready feature extraction structures for binary analysis

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32};

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

/// Control flow graph metrics for a function
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlFlowMetrics {
    /// Number of basic blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub basic_blocks: u32,
    /// Number of control flow edges
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub edges: u32,
    /// Cyclomatic complexity (McCabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cyclomatic_complexity: u32,
    /// Maximum instructions in any basic block
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_block_size: u32,
    /// Average instructions per basic block
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_block_size: f32,
    /// Whether function has linear control flow (no branches)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_linear: bool,
    /// Number of loops detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loop_count: u32,
    /// Branch density (branches per instruction)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub branch_density: f32,
    /// Call graph in-degree (callers)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub in_degree: u32,
    /// Call graph out-degree (callees)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub out_degree: u32,
}

/// Instruction-level analysis for ML features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionAnalysis {
    /// Total instruction count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_instructions: u32,
    /// CPU cycle cost estimate
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instruction_cost: u32,
    /// Instruction density (instructions per byte)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub instruction_density: f32,
    /// Instruction categories and counts
    pub categories: InstructionCategories,
    /// Top 5 most used opcodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_opcodes: Vec<OpcodeFrequency>,
    /// Unusual/suspicious instructions detected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unusual_instructions: Vec<String>,
}

/// Categorized instruction counts for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionCategories {
    /// Arithmetic operations (add, sub, mul, div, inc, dec)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arithmetic: u32,
    /// Logical operations (and, or, xor, not, test)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub logic: u32,
    /// Memory operations (mov, lea, push, pop, load, store)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memory: u32,
    /// Control flow (jmp, jne, call, ret, loop)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub control: u32,
    /// System calls and interrupts (syscall, int, sysenter)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system: u32,
    /// FPU/SIMD operations (fadd, fmul, xmm, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fpu_simd: u32,
    /// String operations (movs, cmps, scas, stos)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_ops: u32,
    /// Privileged instructions (cli, sti, hlt, in, out)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub privileged: u32,
    /// Crypto-related instructions (aes, sha, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto: u32,
}

/// Opcode frequency for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpcodeFrequency {
    pub opcode: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub count: u32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub percentage: f32,
}

/// Register usage patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterUsage {
    /// Registers read in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Registers written in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<String>,
    /// Registers preserved across call
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved: Vec<String>,
    /// Registers used in function (legacy, kept for compatibility)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registers_used: Vec<String>,
    /// Non-standard register usage (unusual for the architecture)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_standard_usage: Vec<String>,
    /// Stack pointer manipulation detected
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_pointer_manipulation: bool,
    /// Frame pointer usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_frame_pointer: bool,
    /// Maximum local variables (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_locals: Option<u32>,
    /// Maximum operand stack depth (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_stack: Option<u32>,
}

/// Embedded constant with decoded information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedConstant {
    /// Raw value as hex string
    pub value: String,
    /// Constant type (qword, dword, word, byte)
    pub constant_type: String,
    /// Possible decoded interpretations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoded: Vec<DecodedValue>,
}

/// Decoded constant value interpretations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecodedValue {
    /// Type of decoded value (ip_address, port, url, key, etc)
    pub value_type: String,
    /// Human-readable decoded value
    pub decoded_value: String,
    /// Confidence in this interpretation (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,
}

/// Function-level properties
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionProperties {
    /// Function is side-effect free (pure)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_pure: bool,
    /// Function never returns
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_noreturn: bool,
    /// Function is recursive
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_recursive: bool,
    /// Stack frame size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stack_frame: u32,
    /// Number of local variables
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_vars: u32,
    /// Number of arguments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args: u32,
    /// Function is a leaf (calls nothing)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_leaf: bool,
}

/// Function signature analysis (source code languages)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionSignature {
    /// Parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub param_count: u32,
    /// Parameters with default values
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_param_count: u32,
    /// Has *args (variadic positional)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_positional: bool,
    /// Has **kwargs (variadic keyword)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_keyword: bool,
    /// Has type annotations/hints
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_type_hints: bool,
    /// Return type annotation present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_return_type: bool,
    /// Decorators applied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<String>,
    /// Is async function
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_async: bool,
    /// Is generator (contains yield)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_generator: bool,
    /// Is lambda/anonymous
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_lambda: bool,
}

/// Nesting depth metrics for control structures
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NestingMetrics {
    /// Maximum nesting depth in function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_depth: f32,
    /// Locations with deep nesting (depth > 4)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub deep_nest_count: u32,
    /// Depth limit was hit during analysis (potential anti-analysis)
    #[serde(default, skip_serializing_if = "is_false")]
    pub depth_limit_hit: bool,
}

/// Call pattern analysis for source code
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallPatternMetrics {
    /// Total function calls in this function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_count: u32,
    /// Unique functions called
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_callees: u32,
    /// Chained method calls (e.g., obj.a().b().c())
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chained_calls: u32,
    /// Maximum chain length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_chain_length: u32,
    /// Recursive calls (self-reference)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_calls: u32,
    /// Dynamic calls (eval, exec, __import__, getattr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_calls: u32,
}

