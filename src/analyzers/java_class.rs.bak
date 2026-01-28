//! Java bytecode (.class) analyzer.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::types::*;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Java class file analyzer for compiled .class bytecode
pub struct JavaClassAnalyzer {
    capability_mapper: CapabilityMapper,
}

impl JavaClassAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        hex::encode(hash)
    }

    fn analyze_class(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        if data.len() < 10 {
            bail!("File too small to be a valid class file");
        }

        // Verify magic
        if &data[0..4] != b"\xCA\xFE\xBA\xBE" {
            bail!("Invalid Java class magic");
        }

        let minor_version = u16::from_be_bytes([data[4], data[5]]);
        let major_version = u16::from_be_bytes([data[6], data[7]]);
        let java_version = Self::major_to_java_version(major_version);

        // Calculate file entropy
        let file_entropy = calculate_entropy(data);
        let entropy_level = EntropyLevel::from_value(file_entropy);

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "class".to_string(),
            size_bytes: data.len() as u64,
            sha256: self.calculate_sha256(data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature for Java class
        report.structure.push(StructuralFeature {
            id: "bytecode/java/class".to_string(),
            desc: format!(
                "Java class file (Java {}, version {}.{})",
                java_version, major_version, minor_version
            ),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "header".to_string(),
                value: format!("CAFEBABE v{}.{}", major_version, minor_version),
                location: Some("0x0".to_string()),
            }],
        });

        // Add entropy structural feature if elevated or high
        if matches!(entropy_level, EntropyLevel::Elevated | EntropyLevel::High) {
            report.structure.push(StructuralFeature {
                id: format!("entropy/{}", entropy_level.as_str()),
                desc: entropy_level.description().to_string(),
                evidence: vec![Evidence {
                    method: "entropy".to_string(),
                    source: "file".to_string(),
                    value: format!("{:.2}", file_entropy),
                    location: None,
                }],
            });
        }

        // Add overall file section with entropy
        report.sections.push(Section {
            name: "class_file".to_string(),
            size: data.len() as u64,
            entropy: file_entropy,
            permissions: None,
        });

        // Parse constant pool and extract information
        if let Ok(class_info) = self.parse_class_file(data) {
            // Add class name
            if let Some(class_name) = &class_info.this_class {
                report.structure.push(StructuralFeature {
                    id: "bytecode/java/class-name".to_string(),
                    desc: format!("Class: {}", class_name),
                    evidence: vec![Evidence {
                        method: "constant_pool".to_string(),
                        source: "class_info".to_string(),
                        value: class_name.clone(),
                        location: None,
                    }],
                });
            }

            // Add superclass
            if let Some(super_class) = &class_info.super_class {
                if super_class != "java/lang/Object" {
                    report.structure.push(StructuralFeature {
                        id: "bytecode/java/superclass".to_string(),
                        desc: format!("Extends: {}", super_class),
                        evidence: vec![Evidence {
                            method: "constant_pool".to_string(),
                            source: "class_info".to_string(),
                            value: super_class.clone(),
                            location: None,
                        }],
                    });
                }
            }

            // Add interfaces
            for iface in &class_info.interfaces {
                report.structure.push(StructuralFeature {
                    id: "bytecode/java/interface".to_string(),
                    desc: format!("Implements: {}", iface),
                    evidence: vec![Evidence {
                        method: "constant_pool".to_string(),
                        source: "class_info".to_string(),
                        value: iface.clone(),
                        location: None,
                    }],
                });
            }

            // Extract strings from constant pool
            for s in &class_info.strings {
                if self.is_interesting_string(s) {
                    report.strings.push(StringInfo {
                        value: s.clone(),
                        offset: None,
                        encoding: "utf8".to_string(),
                        string_type: StringType::Plain,
                        section: Some("constant_pool".to_string()),
                    });
                }
            }

            // Detect capabilities from class references
            self.detect_capabilities(&class_info, &mut report);

            // Add field information as exports (static fields are effectively global constants)
            for field in &class_info.fields {
                let mut desc = self.format_type_descriptor(&field.descriptor);
                if field.is_static {
                    desc = format!("static {}", desc);
                }
                if field.is_final {
                    desc = format!("final {}", desc);
                }

                // Add as export for visibility
                report.exports.push(Export {
                    symbol: format!("{}: {}", field.name, desc),
                    offset: None,
                    source: "java_class".to_string(),
                });

                // If field has a constant value, add as structural feature
                if let Some(ref value) = field.constant_value {
                    report.structure.push(StructuralFeature {
                        id: "bytecode/java/field-value".to_string(),
                        desc: format!("Field {} = {}", field.name, value),
                        evidence: vec![Evidence {
                            method: "constant_pool".to_string(),
                            source: "field_info".to_string(),
                            value: value.clone(),
                            location: None,
                        }],
                    });
                }
            }

            // Add method information as functions
            for method in &class_info.methods {
                let formatted_sig = self.format_method_signature(&method.name, &method.descriptor);
                let properties = FunctionProperties {
                    is_leaf: method.code_length == 0 && !method.is_native,
                    local_vars: method.max_locals as u32,
                    args: self.count_parameters(&method.descriptor),
                    ..Default::default()
                };

                report.functions.push(Function {
                    name: formatted_sig,
                    offset: None,
                    size: if method.code_length > 0 {
                        Some(method.code_length as u64)
                    } else {
                        None
                    },
                    complexity: if method.complexity > 0 {
                        Some(method.complexity)
                    } else {
                        None
                    },
                    calls: vec![],
                    source: "java_class".to_string(),
                    control_flow: Some(ControlFlowMetrics {
                        basic_blocks: 0,
                        edges: 0,
                        cyclomatic_complexity: method.complexity,
                        max_block_size: 0,
                        avg_block_size: 0.0,
                        is_linear: method.complexity <= 1,
                        loop_count: 0,
                        branch_density: 0.0,
                        in_degree: 0,
                        out_degree: 0,
                    }),
                    instruction_analysis: None,
                    register_usage: Some(RegisterUsage {
                        read: vec![],
                        written: vec![],
                        preserved: vec![],
                        registers_used: vec![],
                        non_standard_usage: vec![],
                        stack_pointer_manipulation: false,
                        uses_frame_pointer: false,
                        max_locals: Some(method.max_locals as u32),
                        max_stack: Some(method.max_stack as u32),
                    }),
                    constants: vec![],
                    properties: Some(properties),
                    signature: None,
                    nesting: None,
                    call_patterns: None,
                });
            }

            // Add imports (referenced classes)
            for class_ref in &class_info.class_refs {
                if !class_ref.starts_with("java/") && !class_ref.starts_with("[") {
                    report.imports.push(Import {
                        symbol: class_ref.replace('/', "."),
                        library: None,
                        source: "java_class".to_string(),
                    });
                }
            }
        }

        // Evaluate trait definitions and composite rules
        let trait_findings = self.capability_mapper.evaluate_traits(&report, data);
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, data);

        // Add all findings
        for f in trait_findings
            .into_iter()
            .chain(composite_findings.into_iter())
        {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["java-class-parser".to_string()];

        Ok(report)
    }

    fn major_to_java_version(major: u16) -> String {
        match major {
            45 => "1.1".to_string(),
            46 => "1.2".to_string(),
            47 => "1.3".to_string(),
            48 => "1.4".to_string(),
            49 => "5".to_string(),
            50 => "6".to_string(),
            51 => "7".to_string(),
            52 => "8".to_string(),
            53 => "9".to_string(),
            54 => "10".to_string(),
            55 => "11".to_string(),
            56 => "12".to_string(),
            57 => "13".to_string(),
            58 => "14".to_string(),
            59 => "15".to_string(),
            60 => "16".to_string(),
            61 => "17".to_string(),
            62 => "18".to_string(),
            63 => "19".to_string(),
            64 => "20".to_string(),
            65 => "21".to_string(),
            _ => format!("{}", major - 44),
        }
    }

    fn is_interesting_string(&self, s: &str) -> bool {
        // Filter out very short strings and common Java internal strings
        if s.len() < 4 {
            return false;
        }

        // Skip common Java internal strings
        if s.starts_with("()") || s.starts_with("(L") || s.starts_with("[L") {
            return false;
        }

        // Include URLs, paths, commands, etc.
        if s.contains("http://")
            || s.contains("https://")
            || s.contains('/')
            || s.contains('\\')
            || s.contains(".exe")
            || s.contains(".dll")
            || s.contains(".jar")
            || s.contains("cmd")
            || s.contains("powershell")
            || s.contains("bash")
            || s.contains("password")
            || s.contains("secret")
            || s.contains("key")
            || s.contains("token")
            || s.contains("admin")
            || s.contains("root")
        {
            return true;
        }

        // Include strings that look like they contain meaningful text
        s.chars().filter(|c| c.is_alphabetic()).count() > 3
    }

    /// Format a Java type descriptor into human-readable form
    fn format_type_descriptor(&self, desc: &str) -> String {
        let mut chars = desc.chars().peekable();
        self.parse_type_descriptor(&mut chars)
    }

    fn parse_type_descriptor(&self, chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
        match chars.next() {
            Some('B') => "byte".to_string(),
            Some('C') => "char".to_string(),
            Some('D') => "double".to_string(),
            Some('F') => "float".to_string(),
            Some('I') => "int".to_string(),
            Some('J') => "long".to_string(),
            Some('S') => "short".to_string(),
            Some('Z') => "boolean".to_string(),
            Some('V') => "void".to_string(),
            Some('[') => format!("{}[]", self.parse_type_descriptor(chars)),
            Some('L') => {
                let mut class_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        chars.next();
                        break;
                    }
                    class_name.push(chars.next().unwrap());
                }
                class_name.replace('/', ".")
            }
            _ => "unknown".to_string(),
        }
    }

    /// Format a method signature into human-readable form
    fn format_method_signature(&self, name: &str, desc: &str) -> String {
        let mut chars = desc.chars().peekable();

        // Skip opening paren
        if chars.next() != Some('(') {
            return format!("{}()", name);
        }

        let mut params = Vec::new();
        while chars.peek() != Some(&')') && chars.peek().is_some() {
            params.push(self.parse_type_descriptor(&mut chars));
        }
        chars.next(); // Skip ')'

        let return_type = self.parse_type_descriptor(&mut chars);
        format!("{} {}({})", return_type, name, params.join(", "))
    }

    /// Count parameters from method descriptor
    fn count_parameters(&self, desc: &str) -> u32 {
        let mut chars = desc.chars().peekable();
        if chars.next() != Some('(') {
            return 0;
        }

        let mut count = 0;
        while chars.peek() != Some(&')') && chars.peek().is_some() {
            // Skip array dimensions
            while chars.peek() == Some(&'[') {
                chars.next();
            }
            match chars.peek() {
                Some('L') => {
                    // Object type - skip until ';'
                    while chars.next() != Some(';') {}
                    count += 1;
                }
                Some('B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z') => {
                    chars.next();
                    count += 1;
                }
                _ => break,
            }
        }
        count
    }

    fn parse_class_file(&self, data: &[u8]) -> Result<ClassInfo> {
        let mut info = ClassInfo::default();
        let mut pos = 8; // Skip magic, minor, major

        // Parse constant pool count
        if pos + 2 > data.len() {
            bail!("Unexpected end of class file");
        }
        let cp_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Parse constant pool
        let mut constant_pool: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Empty; cp_count];
        let mut i = 1;
        while i < cp_count {
            if pos >= data.len() {
                break;
            }
            let tag = data[pos];
            pos += 1;

            match tag {
                1 => {
                    // CONSTANT_Utf8
                    if pos + 2 > data.len() {
                        break;
                    }
                    let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + length > data.len() {
                        break;
                    }
                    if let Ok(s) = String::from_utf8(data[pos..pos + length].to_vec()) {
                        info.strings.insert(s.clone());
                        constant_pool[i] = ConstantPoolEntry::Utf8(s);
                    }
                    pos += length;
                }
                3 => {
                    // CONSTANT_Integer
                    if pos + 4 > data.len() {
                        break;
                    }
                    let val = i32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    constant_pool[i] = ConstantPoolEntry::Integer(val);
                    pos += 4;
                }
                4 => {
                    // CONSTANT_Float
                    if pos + 4 > data.len() {
                        break;
                    }
                    let bits = u32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    constant_pool[i] = ConstantPoolEntry::Float(f32::from_bits(bits));
                    pos += 4;
                }
                5 => {
                    // CONSTANT_Long
                    if pos + 8 > data.len() {
                        break;
                    }
                    let val = i64::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                        data[pos + 4],
                        data[pos + 5],
                        data[pos + 6],
                        data[pos + 7],
                    ]);
                    constant_pool[i] = ConstantPoolEntry::Long(val);
                    pos += 8;
                    i += 1; // Long takes 2 slots
                }
                6 => {
                    // CONSTANT_Double
                    if pos + 8 > data.len() {
                        break;
                    }
                    let bits = u64::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                        data[pos + 4],
                        data[pos + 5],
                        data[pos + 6],
                        data[pos + 7],
                    ]);
                    constant_pool[i] = ConstantPoolEntry::Double(f64::from_bits(bits));
                    pos += 8;
                    i += 1; // Double takes 2 slots
                }
                7 => {
                    // CONSTANT_Class
                    if pos + 2 > data.len() {
                        break;
                    }
                    let name_index = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    constant_pool[i] = ConstantPoolEntry::Class(name_index);
                    pos += 2;
                }
                8 => {
                    // CONSTANT_String
                    if pos + 2 > data.len() {
                        break;
                    }
                    let string_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    constant_pool[i] = ConstantPoolEntry::String(string_idx);
                    pos += 2;
                }
                9..=11 => {
                    // CONSTANT_Fieldref, Methodref, InterfaceMethodref
                    if pos + 4 > data.len() {
                        break;
                    }
                    let class_index = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let name_type_index = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    constant_pool[i] = ConstantPoolEntry::MethodRef(class_index, name_type_index);
                    pos += 4;
                }
                12 => {
                    // CONSTANT_NameAndType
                    if pos + 4 > data.len() {
                        break;
                    }
                    let name_index = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let desc_index = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    constant_pool[i] = ConstantPoolEntry::NameAndType(name_index, desc_index);
                    pos += 4;
                }
                15 => {
                    // CONSTANT_MethodHandle
                    pos += 3;
                }
                16 => {
                    // CONSTANT_MethodType
                    pos += 2;
                }
                17 | 18 => {
                    // CONSTANT_Dynamic, CONSTANT_InvokeDynamic
                    pos += 4;
                }
                19 | 20 => {
                    // CONSTANT_Module, CONSTANT_Package
                    pos += 2;
                }
                _ => {
                    // Unknown tag, try to continue
                    break;
                }
            }
            i += 1;
        }

        // Resolve class references from constant pool
        for entry in &constant_pool {
            if let ConstantPoolEntry::Class(name_idx) = entry {
                if let Some(ConstantPoolEntry::Utf8(name)) = constant_pool.get(*name_idx as usize) {
                    info.class_refs.insert(name.clone());
                }
            }
        }

        // Parse access flags, this_class, super_class
        if pos + 6 > data.len() {
            return Ok(info);
        }
        info.access_flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let this_class_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let super_class_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
        pos += 6;

        // Resolve this_class name
        if let Some(ConstantPoolEntry::Class(name_idx)) = constant_pool.get(this_class_idx as usize)
        {
            if let Some(ConstantPoolEntry::Utf8(name)) = constant_pool.get(*name_idx as usize) {
                info.this_class = Some(name.clone());
            }
        }

        // Resolve super_class name
        if super_class_idx != 0 {
            if let Some(ConstantPoolEntry::Class(name_idx)) =
                constant_pool.get(super_class_idx as usize)
            {
                if let Some(ConstantPoolEntry::Utf8(name)) = constant_pool.get(*name_idx as usize) {
                    info.super_class = Some(name.clone());
                }
            }
        }

        // Parse interfaces count
        if pos + 2 > data.len() {
            return Ok(info);
        }
        let interfaces_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Parse interfaces
        for _ in 0..interfaces_count {
            if pos + 2 > data.len() {
                break;
            }
            let iface_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            if let Some(ConstantPoolEntry::Class(name_idx)) = constant_pool.get(iface_idx as usize)
            {
                if let Some(ConstantPoolEntry::Utf8(name)) = constant_pool.get(*name_idx as usize) {
                    info.interfaces.push(name.clone());
                }
            }
        }

        // Parse fields
        if pos + 2 > data.len() {
            return Ok(info);
        }
        let fields_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        for _ in 0..fields_count {
            if pos + 8 > data.len() {
                break;
            }
            let access_flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
            let attrs_count = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;

            let field_name = self
                .get_utf8(&constant_pool, name_idx)
                .unwrap_or_else(|| format!("field_{}", name_idx));
            let field_desc = self.get_utf8(&constant_pool, desc_idx).unwrap_or_default();

            let mut constant_value = None;

            // Parse field attributes to look for ConstantValue
            for _ in 0..attrs_count {
                if pos + 6 > data.len() {
                    break;
                }
                let attr_name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let attr_len = u32::from_be_bytes([
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                ]) as usize;
                pos += 6;

                let attr_name = self.get_utf8(&constant_pool, attr_name_idx);
                if attr_name.as_deref() == Some("ConstantValue")
                    && attr_len >= 2
                    && pos + attr_len <= data.len()
                {
                    let const_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    constant_value = self.get_constant_value(&constant_pool, const_idx);
                }
                pos += attr_len;
            }

            info.fields.push(FieldInfo {
                name: field_name,
                descriptor: field_desc,
                is_public: (access_flags & 0x0001) != 0,
                is_static: (access_flags & 0x0008) != 0,
                is_final: (access_flags & 0x0010) != 0,
                constant_value,
            });
        }

        // Parse methods
        if pos + 2 > data.len() {
            return Ok(info);
        }
        let methods_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        for _ in 0..methods_count {
            if pos + 8 > data.len() {
                break;
            }
            let access_flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
            let attrs_count = u16::from_be_bytes([data[pos + 6], data[pos + 7]]) as usize;
            pos += 8;

            let method_name = self
                .get_utf8(&constant_pool, name_idx)
                .unwrap_or_else(|| format!("method_{}", name_idx));
            let method_desc = self.get_utf8(&constant_pool, desc_idx).unwrap_or_default();

            let mut code_length = 0u32;
            let mut max_stack = 0u16;
            let mut max_locals = 0u16;
            let mut complexity = 0u32;

            // Parse method attributes to find Code attribute
            for _ in 0..attrs_count {
                if pos + 6 > data.len() {
                    break;
                }
                let attr_name_idx = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let attr_len = u32::from_be_bytes([
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                ]) as usize;
                pos += 6;

                let attr_name = self.get_utf8(&constant_pool, attr_name_idx);
                if attr_name.as_deref() == Some("Code")
                    && attr_len >= 8
                    && pos + attr_len <= data.len()
                {
                    // Code attribute structure:
                    // u2 max_stack, u2 max_locals, u4 code_length, code[code_length], ...
                    max_stack = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    max_locals = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                    code_length = u32::from_be_bytes([
                        data[pos + 4],
                        data[pos + 5],
                        data[pos + 6],
                        data[pos + 7],
                    ]);

                    // Analyze bytecode for complexity (count branch instructions)
                    if code_length > 0 && pos + 8 + code_length as usize <= data.len() {
                        let bytecode = &data[pos + 8..pos + 8 + code_length as usize];
                        complexity = self.calculate_bytecode_complexity(bytecode);
                    }
                }
                pos += attr_len;
            }

            info.methods.push(MethodInfo {
                name: method_name,
                descriptor: method_desc,
                is_public: (access_flags & 0x0001) != 0,
                is_static: (access_flags & 0x0008) != 0,
                is_native: (access_flags & 0x0100) != 0,
                is_synchronized: (access_flags & 0x0020) != 0,
                code_length,
                max_stack,
                max_locals,
                complexity,
            });
        }

        Ok(info)
    }

    fn get_utf8(&self, pool: &[ConstantPoolEntry], idx: u16) -> Option<String> {
        match pool.get(idx as usize) {
            Some(ConstantPoolEntry::Utf8(s)) => Some(s.clone()),
            _ => None,
        }
    }

    fn get_constant_value(&self, pool: &[ConstantPoolEntry], idx: u16) -> Option<String> {
        match pool.get(idx as usize) {
            Some(ConstantPoolEntry::Integer(v)) => Some(v.to_string()),
            Some(ConstantPoolEntry::Float(v)) => Some(format!("{:.6}", v)),
            Some(ConstantPoolEntry::Long(v)) => Some(format!("{}L", v)),
            Some(ConstantPoolEntry::Double(v)) => Some(format!("{:.6}D", v)),
            Some(ConstantPoolEntry::String(str_idx)) => self.get_utf8(pool, *str_idx),
            Some(ConstantPoolEntry::Utf8(s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Calculate cyclomatic complexity from Java bytecode
    /// Counts branch instructions as decision points
    fn calculate_bytecode_complexity(&self, bytecode: &[u8]) -> u32 {
        let mut complexity = 1u32; // Base complexity
        let mut pc = 0;

        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            // Count branch instructions as complexity contributors
            match opcode {
                // Conditional branches (if_*)
                0x99..=0xa6 => complexity += 1, // ifeq, ifne, iflt, ifge, ifgt, ifle, if_icmpeq, etc.
                // Compound conditionals
                0xa7 => {} // goto - not a decision point
                0xa8 => {} // jsr
                0xa9 => {} // ret
                // Table/lookup switch
                0xaa => {
                    // tableswitch
                    let padding = (4 - ((pc + 1) % 4)) % 4;
                    if pc + 1 + padding + 12 <= bytecode.len() {
                        let base = pc + 1 + padding;
                        let low = i32::from_be_bytes([
                            bytecode[base + 4],
                            bytecode[base + 5],
                            bytecode[base + 6],
                            bytecode[base + 7],
                        ]);
                        let high = i32::from_be_bytes([
                            bytecode[base + 8],
                            bytecode[base + 9],
                            bytecode[base + 10],
                            bytecode[base + 11],
                        ]);
                        complexity += (high - low + 1) as u32; // Each case is a decision
                        pc = base + 12 + ((high - low + 1) as usize * 4);
                        continue;
                    }
                }
                0xab => {
                    // lookupswitch
                    let padding = (4 - ((pc + 1) % 4)) % 4;
                    if pc + 1 + padding + 8 <= bytecode.len() {
                        let base = pc + 1 + padding;
                        let npairs = i32::from_be_bytes([
                            bytecode[base + 4],
                            bytecode[base + 5],
                            bytecode[base + 6],
                            bytecode[base + 7],
                        ]);
                        complexity += npairs as u32; // Each match-value pair
                        pc = base + 8 + (npairs as usize * 8);
                        continue;
                    }
                }
                // Exception handling (athrow)
                0xbf => complexity += 1,
                // Null checks (can throw)
                0xc6 | 0xc7 => complexity += 1, // ifnull, ifnonnull
                _ => {}
            }
            pc += self.bytecode_instruction_length(opcode, &bytecode[pc..]);
        }
        complexity
    }

    fn bytecode_instruction_length(&self, opcode: u8, _bytecode: &[u8]) -> usize {
        match opcode {
            // No operands (1 byte)
            0x00..=0x0f
            | 0x1a..=0x35
            | 0x3b..=0x83
            | 0x85..=0x98
            | 0xac..=0xb1
            | 0xbe
            | 0xbf
            | 0xc2
            | 0xc3
            | 0xca..=0xff => 1,
            // 1 operand byte
            0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3a | 0xa9 | 0xbc => 2,
            // 2 operand bytes
            0x11
            | 0x13
            | 0x14
            | 0x84
            | 0x99..=0xa8
            | 0xb2..=0xb5
            | 0xb6..=0xb9
            | 0xbb
            | 0xbd
            | 0xc0
            | 0xc1
            | 0xc6
            | 0xc7 => 3,
            // 4 operand bytes
            0xc8 | 0xc9 => 5,
            // Variable length (handled separately for tableswitch/lookupswitch)
            0xaa | 0xab => 1, // Will be handled in complexity calculation
            // invokeinterface, invokedynamic
            0xba => 5,
            // wide prefix
            0xc4 => 4, // Minimum, could be 6 for iinc_w
            _ => 1,
        }
    }

    fn detect_capabilities(&self, class_info: &ClassInfo, report: &mut AnalysisReport) {
        // Detect suspicious class references
        let suspicious_classes = [
            (
                "java/lang/Runtime",
                "exec/process",
                "Process execution capability",
            ),
            (
                "java/lang/ProcessBuilder",
                "exec/process",
                "Process execution via ProcessBuilder",
            ),
            ("java/net/Socket", "net/socket", "Network socket operations"),
            (
                "java/net/ServerSocket",
                "net/server",
                "Network server socket",
            ),
            ("java/net/URL", "net/http", "URL/HTTP operations"),
            ("java/net/URLConnection", "net/http", "HTTP connection"),
            ("java/net/HttpURLConnection", "net/http", "HTTP operations"),
            ("javax/net/ssl", "net/ssl", "SSL/TLS operations"),
            ("java/io/File", "fs/file", "File system operations"),
            ("java/nio/file", "fs/file", "NIO file operations"),
            (
                "java/lang/reflect",
                "reflect/invoke",
                "Reflection capabilities",
            ),
            (
                "java/lang/ClassLoader",
                "reflect/classloader",
                "Dynamic class loading",
            ),
            ("javax/crypto", "crypto/cipher", "Cryptographic operations"),
            ("java/security", "crypto/security", "Security operations"),
            ("java/util/zip", "archive/zip", "ZIP archive operations"),
            ("java/util/jar", "archive/jar", "JAR archive operations"),
            ("java/sql", "data/sql", "SQL database operations"),
            (
                "javax/naming",
                "net/jndi",
                "JNDI operations (potential for injection)",
            ),
            ("java/rmi", "net/rmi", "Remote Method Invocation"),
            (
                "java/awt/Robot",
                "ui/automation",
                "UI automation (keylogger potential)",
            ),
            (
                "java/lang/System",
                "intel/system",
                "System information access",
            ),
            ("java/lang/Thread", "exec/thread", "Thread manipulation"),
            ("sun/misc/Unsafe", "mem/unsafe", "Unsafe memory operations"),
        ];

        for class_ref in &class_info.class_refs {
            for (pattern, cap_id, description) in &suspicious_classes {
                if class_ref.starts_with(pattern) || class_ref.contains(pattern) {
                    if !report.findings.iter().any(|c| c.id == *cap_id) {
                        report.findings.push(Finding {
                            kind: FindingKind::Capability,
                            trait_refs: vec![],
                            id: cap_id.to_string(),
                            desc: description.to_string(),
                            conf: 0.9,
                            crit: if cap_id.contains("exec") || cap_id.contains("unsafe") {
                                Criticality::Hostile
                            } else if cap_id.contains("net") || cap_id.contains("reflect") {
                                Criticality::Suspicious
                            } else {
                                Criticality::Notable
                            },
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "class_reference".to_string(),
                                source: "constant_pool".to_string(),
                                value: class_ref.clone(),
                                location: None,
                            }],
                        });
                    }
                    break;
                }
            }
        }

        // Detect suspicious method names
        for method in &class_info.methods {
            let method_lower = method.name.to_lowercase();
            if method_lower.contains("decrypt") || method_lower.contains("encrypt") {
                self.add_capability(
                    report,
                    "crypto/operation",
                    "Encryption/decryption operation",
                    &method.name,
                    Criticality::Suspicious,
                );
            }
            if method_lower.contains("exec")
                || method_lower.contains("command")
                || method_lower.contains("shell")
            {
                self.add_capability(
                    report,
                    "exec/command",
                    "Command execution method",
                    &method.name,
                    Criticality::Hostile,
                );
            }
            if method_lower.contains("download") || method_lower.contains("upload") {
                self.add_capability(
                    report,
                    "net/transfer",
                    "File transfer operation",
                    &method.name,
                    Criticality::Suspicious,
                );
            }
            if method_lower.contains("inject") || method_lower.contains("hook") {
                self.add_capability(
                    report,
                    "exec/inject",
                    "Code injection method",
                    &method.name,
                    Criticality::Hostile,
                );
            }
            if method_lower.contains("keylog") || method_lower.contains("capture") {
                self.add_capability(
                    report,
                    "credential/keylogger",
                    "Potential keylogging",
                    &method.name,
                    Criticality::Hostile,
                );
            }
        }

        // Detect suspicious strings (RAT commands, malware indicators)
        for s in &class_info.strings {
            let s_lower = s.to_lowercase();

            // Shell/command execution
            if s_lower.contains("cmd.exe")
                || s_lower.contains("powershell")
                || s_lower.contains("power-shell")
                || s_lower.contains("pwsh")
                || s_lower.contains("/bin/sh")
                || s_lower.contains("/bin/bash")
            {
                self.add_capability(
                    report,
                    "exec/shell",
                    "Shell command string",
                    s,
                    Criticality::Hostile,
                );
            }

            // URL references
            if s.contains("http://") || s.contains("https://") {
                self.add_capability(report, "net/url", "URL reference", s, Criticality::Notable);
            }

            // Credential/password stealing
            if s_lower.contains("password")
                || s_lower.contains("credential")
                || s_lower.contains("-pass")
                || s_lower.contains("_pass")
                || s_lower.contains("chrome-pass")
                || s_lower.contains("fox-pass")
                || s_lower.contains("browser") && s_lower.contains("pass")
            {
                self.add_capability(
                    report,
                    "credential/password",
                    "Credential stealing indicator",
                    s,
                    Criticality::Hostile,
                );
            }

            // Keylogging
            if s_lower.contains("keylog")
                || s_lower.contains("key-log")
                || s_lower.contains("o-keylogger")
                || s_lower.contains("keystroke")
            {
                self.add_capability(
                    report,
                    "credential/keylogger",
                    "Keylogger indicator",
                    s,
                    Criticality::Hostile,
                );
            }

            // Encryption/decryption (common in RATs)
            if s_lower.contains("decrypt")
                || s_lower.contains("encrypt")
                || s_lower.contains("rw-decrypt")
                || s_lower.contains("rw-encrypt")
            {
                self.add_capability(
                    report,
                    "crypto/operation",
                    "Encryption/decryption operation",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Download and execute
            if s_lower.contains("up-n-exec")
                || s_lower.contains("download") && s_lower.contains("exec")
                || s_lower.contains("dropper")
                || s_lower.contains("payload")
            {
                self.add_capability(
                    report,
                    "c2/dropper",
                    "Download and execute capability",
                    s,
                    Criticality::Hostile,
                );
            }

            // System control
            if s_lower.contains("reboot")
                || s_lower.contains("shutdown")
                || s_lower.contains("uninstall")
                || s_lower.contains("self-destruct")
            {
                self.add_capability(
                    report,
                    "impact/control",
                    "System control capability",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Privilege escalation
            if s_lower.contains("priv")
                && (s_lower.contains("req") || s_lower.contains("chk") || s_lower.contains("esc"))
                || s_lower.contains("elevate")
                || s_lower.contains("admin")
            {
                self.add_capability(
                    report,
                    "privesc/indicator",
                    "Privilege escalation indicator",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Remote access indicators
            if s_lower.contains("rat")
                || s_lower.contains("c2")
                || s_lower.contains("c&c")
                || s_lower.contains("beacon")
                || s_lower.contains("implant")
                || s_lower.contains("backdoor")
                || s_lower.contains("reverse") && s_lower.contains("shell")
            {
                self.add_capability(
                    report,
                    "impact/remote-access",
                    "Remote access trojan indicator",
                    s,
                    Criticality::Hostile,
                );
            }

            // File operations
            if s_lower.contains("file-manager")
                || s_lower.contains("browse-file")
                || s_lower.contains("upload")
                || s_lower.contains("exfil")
            {
                self.add_capability(
                    report,
                    "exfil/data",
                    "Data exfiltration capability",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Screen capture
            if s_lower.contains("screenshot")
                || s_lower.contains("screen-cap")
                || s_lower.contains("desktop") && s_lower.contains("capture")
            {
                self.add_capability(
                    report,
                    "exfil/screenshot",
                    "Screenshot capability",
                    s,
                    Criticality::Hostile,
                );
            }

            // Webcam/microphone
            if s_lower.contains("webcam")
                || s_lower.contains("camera")
                || s_lower.contains("microphone")
                || s_lower.contains("audio-record")
            {
                self.add_capability(
                    report,
                    "exfil/av-capture",
                    "Audio/video capture capability",
                    s,
                    Criticality::Hostile,
                );
            }
        }
    }

    fn add_capability(
        &self,
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        evidence_value: &str,
        crit: Criticality,
    ) {
        if !report.findings.iter().any(|c| c.id == id) {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: id.to_string(),
                desc: desc.to_string(),
                conf: 0.85,
                crit,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "string_analysis".to_string(),
                    source: "constant_pool".to_string(),
                    value: evidence_value.to_string(),
                    location: None,
                }],
            });
        }
    }
}

impl Default for JavaClassAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JavaClassAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read class file")?;
        self.analyze_class(file_path, &data)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            return ext == "class";
        }
        // Also check magic
        if let Ok(data) = fs::read(file_path) {
            return data.len() >= 4 && &data[0..4] == b"\xCA\xFE\xBA\xBE";
        }
        false
    }
}

#[derive(Default)]
struct ClassInfo {
    this_class: Option<String>,
    super_class: Option<String>,
    interfaces: Vec<String>,
    strings: HashSet<String>,
    class_refs: HashSet<String>,
    methods: Vec<MethodInfo>,
    fields: Vec<FieldInfo>,
    access_flags: u16,
}

#[allow(dead_code)]
struct MethodInfo {
    name: String,
    descriptor: String,
    is_public: bool,
    is_static: bool,
    is_native: bool,
    is_synchronized: bool,
    code_length: u32,
    max_stack: u16,
    max_locals: u16,
    complexity: u32,
}

#[allow(dead_code)]
struct FieldInfo {
    name: String,
    descriptor: String,
    is_public: bool,
    is_static: bool,
    is_final: bool,
    constant_value: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone)]
enum ConstantPoolEntry {
    Empty,
    Utf8(String),
    Class(u16),
    MethodRef(u16, u16),
    NameAndType(u16, u16),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    String(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_analyze_class_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("Test.class")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.java")));
    }

    #[test]
    fn test_major_version_mapping() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(52), "8");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(55), "11");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(61), "17");
    }
}
