use crate::types::{Capability, ControlFlowMetrics, Criticality, Evidence, Function, InstructionAnalysis, BinaryProperties};

/// Maps low-level structural traits to Malware Behavior Catalog capabilities
pub struct TraitMapper;

impl TraitMapper {
    /// Analyze function traits and generate behavioral capabilities
    pub fn analyze_function(func: &Function) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // Analyze control flow metrics
        if let Some(ref cf) = func.control_flow {
            capabilities.extend(Self::analyze_control_flow(cf, &func.name));
        }

        // Analyze instruction patterns
        if let Some(ref instr) = func.instruction_analysis {
            capabilities.extend(Self::analyze_instructions(instr, &func.name));
        }

        // Analyze constants for C2
        if !func.constants.is_empty() {
            capabilities.extend(Self::analyze_constants(&func.constants, &func.name));
        }

        // Analyze function properties
        if let Some(ref props) = func.properties {
            if props.is_noreturn {
                capabilities.push(Capability {
                    id: "exec/terminate".to_string(),
                    description: "Function terminates execution".to_string(),
                    confidence: 0.7,
                    criticality: Criticality::None,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: "noreturn".to_string(),
                        location: Some(func.name.clone()),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }
        }

        capabilities
    }

    /// Analyze control flow metrics for behavioral patterns
    fn analyze_control_flow(cf: &ControlFlowMetrics, func_name: &str) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // High complexity with loops -> potential crypto/packing
        if cf.cyclomatic_complexity > 10 && cf.loop_count > 0 {
            capabilities.push(Capability {
                id: "complexity/high".to_string(),
                description: "High cyclomatic complexity with loops".to_string(),
                confidence: 0.7,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("complexity={}, loops={}", cf.cyclomatic_complexity, cf.loop_count),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });

            // If very high complexity, could be obfuscation
            if cf.cyclomatic_complexity > 20 {
                capabilities.push(Capability {
                    id: "anti-analysis/obfuscation/control-flow".to_string(),
                    description: "Control flow obfuscation detected".to_string(),
                    confidence: 0.6,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: format!("complexity={}", cf.cyclomatic_complexity),
                        location: Some(func_name.to_string()),
                    }],
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }
        }

        // Multiple loops -> potential crypto operation
        if cf.loop_count >= 2 {
            capabilities.push(Capability {
                id: "data/encode".to_string(),
                description: "Multiple nested loops suggest encoding/crypto".to_string(),
                confidence: 0.5,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("loops={}", cf.loop_count),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        capabilities
    }

    /// Analyze instruction patterns for behaviors
    fn analyze_instructions(instr: &InstructionAnalysis, func_name: &str) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // Anti-debug instructions
        for unusual_inst in &instr.unusual_instructions {
            match unusual_inst.as_str() {
                "int1" | "int 1" | "icebp" => {
                    capabilities.push(Capability {
                        id: "anti-analysis/anti-debug/debugger-detect".to_string(),
                        description: "Debug trap instruction detected".to_string(),
                        confidence: 0.9,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                        evidence: vec![Evidence {
                            method: "trait".to_string(),
                            source: "radare2".to_string(),
                            value: unusual_inst.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
                "int3" | "int 3" => {
                    capabilities.push(Capability {
                        id: "anti-analysis/anti-debug/breakpoint".to_string(),
                        description: "Breakpoint instruction detected".to_string(),
                        confidence: 0.8,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                        evidence: vec![Evidence {
                            method: "trait".to_string(),
                            source: "radare2".to_string(),
                            value: unusual_inst.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
                "rdtsc" | "rdtscp" => {
                    capabilities.push(Capability {
                        id: "anti-analysis/anti-debug/timing".to_string(),
                        description: "Timing check via RDTSC".to_string(),
                        confidence: 0.8,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                        evidence: vec![Evidence {
                            method: "trait".to_string(),
                            source: "radare2".to_string(),
                            value: unusual_inst.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
                s if s.contains("cpuid") => {
                    capabilities.push(Capability {
                        id: "anti-analysis/anti-vm/cpu-detect".to_string(),
                        description: "CPU detection via CPUID".to_string(),
                        confidence: 0.7,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                        evidence: vec![Evidence {
                            method: "trait".to_string(),
                            source: "radare2".to_string(),
                            value: unusual_inst.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
                s if s.starts_with("fx") => {
                    // FPU instructions in suspicious context
                    capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/fpu".to_string(),
                        description: "FPU instructions used for obfuscation".to_string(),
                        confidence: 0.6,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                        evidence: vec![Evidence {
                            method: "trait".to_string(),
                            source: "radare2".to_string(),
                            value: unusual_inst.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
                _ => {}
            }
        }

        // High ratio of XOR operations -> encoding/crypto
        let xor_ratio = instr.categories.logic as f32 / instr.total_instructions as f32;
        if xor_ratio > 0.2 && instr.total_instructions > 10 {
            capabilities.push(Capability {
                id: "crypto/xor".to_string(),
                description: "High XOR operation density suggests encoding".to_string(),
                confidence: 0.6,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("xor_ratio={:.2}", xor_ratio),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Crypto instructions
        if instr.categories.crypto > 0 {
            capabilities.push(Capability {
                id: "crypto/encrypt".to_string(),
                description: "Hardware crypto instructions detected".to_string(),
                confidence: 0.9,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("crypto_instructions={}", instr.categories.crypto),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // String operations with loops -> data manipulation
        if instr.categories.string_ops > 3 {
            capabilities.push(Capability {
                id: "data/encoding/string-ops".to_string(),
                description: "String operations for data manipulation".to_string(),
                confidence: 0.6,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("string_ops={}", instr.categories.string_ops),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // System calls
        if instr.categories.system > 0 {
            capabilities.push(Capability {
                id: "os/syscall".to_string(),
                description: "Direct system call usage".to_string(),
                confidence: 0.8,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("syscalls={}", instr.categories.system),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Privileged instructions -> rootkit behavior
        if instr.categories.privileged > 0 {
            capabilities.push(Capability {
                id: "privilege/escalate".to_string(),
                description: "Privileged instructions detected".to_string(),
                confidence: 0.7,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("privileged={}", instr.categories.privileged),
                    location: Some(func_name.to_string()),
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        capabilities
    }

    /// Analyze embedded constants for C2 indicators
    fn analyze_constants(constants: &[crate::types::EmbeddedConstant], func_name: &str) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        for constant in constants {
            for decoded in &constant.decoded {
                match decoded.value_type.as_str() {
                    "ip_address" | "ip_port" => {
                        capabilities.push(Capability {
                            id: "net/c2/address".to_string(),
                            description: format!("Embedded C2 address: {}", decoded.decoded_value),
                            confidence: decoded.confidence,
                            criticality: Criticality::None,
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "constant_decode".to_string(),
                                source: "radare2".to_string(),
                                value: decoded.decoded_value.clone(),
                                location: Some(func_name.to_string()),
                            }],
                            traits: Vec::new(),
                            referenced_paths: None,
                            referenced_directories: None,
                        });
                    }
                    "port" => {
                        capabilities.push(Capability {
                            id: "net/socket/listen".to_string(),
                            description: format!("Embedded port number: {}", decoded.decoded_value),
                            confidence: decoded.confidence * 0.7, // Lower confidence for ports alone
                            criticality: Criticality::Low,
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "constant_decode".to_string(),
                                source: "radare2".to_string(),
                                value: decoded.decoded_value.clone(),
                                location: Some(func_name.to_string()),
                            }],
                            traits: Vec::new(),
                        referenced_paths: None,
                        referenced_directories: None,
                        });
                    }
                    _ => {}
                }
            }
        }

        capabilities
    }

    /// Analyze binary-wide properties for capabilities
    pub fn analyze_binary_properties(props: &BinaryProperties) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // No security features -> suspicious
        if !props.security.canary && !props.security.nx && !props.security.pic {
            capabilities.push(Capability {
                id: "binary/security/none".to_string(),
                description: "No security hardening features present".to_string(),
                confidence: 1.0,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: "no_canary,no_nx,no_pic".to_string(),
                    location: None,
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Stripped binary -> anti-analysis
        if props.security.stripped {
            capabilities.push(Capability {
                id: "anti-analysis/stripped".to_string(),
                description: "Binary symbols stripped".to_string(),
                confidence: 1.0,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: "stripped".to_string(),
                    location: None,
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Static linking -> evasion
        if props.linking.is_static {
            capabilities.push(Capability {
                id: "binary/linking/static".to_string(),
                description: "Statically linked binary".to_string(),
                confidence: 1.0,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: "static".to_string(),
                    location: None,
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Anomalies
        for anomaly in &props.anomalies {
            let capability_id = match anomaly.anomaly_type.as_str() {
                "no_section_header" => "anti-analysis/format/no-sections",
                "overlapping_functions" => "anti-analysis/format/overlapping",
                "unusual_entry_point" => "anti-analysis/format/entry-point",
                _ => "binary/anomaly",
            };

            capabilities.push(Capability {
                id: capability_id.to_string(),
                description: anomaly.description.clone(),
                confidence: 0.8,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        traits: Vec::new(),
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: anomaly.anomaly_type.clone(),
                    location: None,
                }],
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        capabilities
    }
}
