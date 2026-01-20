use crate::types::*;
use std::collections::HashMap;

/// Extract paths from strings and categorize them
pub fn extract_paths_from_strings(strings: &[StringInfo]) -> Vec<PathInfo> {
    let mut paths = Vec::new();

    for string_info in strings {
        if string_info.string_type == StringType::Path {
            let path_info = analyze_path(&string_info.value, "strings");
            paths.push(path_info);
        }
    }

    paths
}

/// Analyze a single path string and categorize it
fn analyze_path(path_str: &str, source: &str) -> PathInfo {
    let path_type = classify_path_type(path_str);
    let category = classify_path_category(path_str);
    let access_type = None; // Would need function analysis to determine

    PathInfo {
        path: path_str.to_string(),
        path_type,
        category,
        access_type,
        source: source.to_string(),
        evidence: vec![Evidence {
            method: "string_pattern".to_string(),
            source: source.to_string(),
            value: path_str.to_string(),
            location: None,
        }],
        referenced_by_traits: Vec::new(),
    }
}

/// Classify path type (absolute, relative, dynamic)
fn classify_path_type(path: &str) -> PathType {
    // Check for format strings (%s, %d, ${VAR})
    if path.contains("%s") || path.contains("%d") || path.contains("${") || path.contains("$HOME") {
        return PathType::Dynamic;
    }

    // Check for relative paths
    if path.starts_with("./") || path.starts_with("../") || path.contains("/../") {
        return PathType::Relative;
    }

    // Default to absolute
    PathType::Absolute
}

/// Classify path category based on common patterns
fn classify_path_category(path: &str) -> PathCategory {
    // Hidden files (starts with . or contains /.)
    if path.starts_with('.') || path.contains("/.") {
        return PathCategory::Hidden;
    }

    // System paths
    if path.starts_with("/bin/") || path.starts_with("/sbin/") ||
       path.starts_with("/usr/bin/") || path.starts_with("/usr/sbin/") ||
       path.starts_with("/lib/") || path.starts_with("/usr/lib/") {
        return PathCategory::System;
    }

    // Config paths
    if path.starts_with("/etc/") || path.ends_with(".conf") ||
       path.contains("/.config/") || path.contains("/Config/") {
        return PathCategory::Config;
    }

    // Temp paths
    if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") ||
       path.starts_with("/dev/shm/") {
        return PathCategory::Temp;
    }

    // Log paths
    if path.starts_with("/var/log/") || path.ends_with(".log") {
        return PathCategory::Log;
    }

    // Home paths
    if path.starts_with("/home/") || path.starts_with("~/") ||
       path == "$HOME" || path.contains("${HOME}") {
        return PathCategory::Home;
    }

    // Device/mount paths
    if path.starts_with("/dev/") || path.starts_with("/mnt/") ||
       path.starts_with("/proc/") || path.starts_with("/sys/") {
        return PathCategory::Device;
    }

    // Runtime paths
    if path.starts_with("/var/run/") || path.starts_with("/run/") {
        return PathCategory::Runtime;
    }

    // Network config
    if path == "/etc/hosts" || path == "/etc/resolv.conf" ||
       path == "/etc/hostname" || path.starts_with("/etc/network/") {
        return PathCategory::Network;
    }

    PathCategory::Other
}

/// Group paths by directory
pub fn group_into_directories(paths: &[PathInfo]) -> Vec<DirectoryAccess> {
    let mut dir_map: HashMap<String, Vec<&PathInfo>> = HashMap::new();

    // Group paths by directory
    for path_info in paths {
        if let Some(parent) = get_parent_directory(&path_info.path) {
            dir_map.entry(parent).or_default().push(path_info);
        }
    }

    let mut directory_accesses = Vec::new();

    for (dir, dir_paths) in dir_map {
        // Skip if only 1 file (not a pattern)
        if dir_paths.len() < 2 {
            continue;
        }

        let files: Vec<String> = dir_paths
            .iter()
            .map(|p| {
                p.path
                    .trim_start_matches(&dir)
                    .trim_start_matches('/')
                    .to_string()
            })
            .collect();

        let file_count = files.len();

        let categories: Vec<PathCategory> = dir_paths
            .iter()
            .map(|p| p.category)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let access_pattern = determine_access_pattern(&files, &dir_paths);

        directory_accesses.push(DirectoryAccess {
            directory: dir.clone(),
            files,
            file_count,
            access_pattern,
            categories,
            enumerated: false, // Would need function analysis
            generated_traits: Vec::new(),
        });
    }

    directory_accesses
}

/// Extract parent directory from path
fn get_parent_directory(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');

    if let Some(last_slash) = path.rfind('/') {
        if last_slash == 0 {
            // Root directory files like /etc/passwd -> /
            return Some("/".to_string());
        }
        Some(format!("{}/", &path[..last_slash]))
    } else {
        None
    }
}

/// Determine access pattern from file list
fn determine_access_pattern(files: &[String], paths: &[&PathInfo]) -> DirectoryAccessPattern {
    // Check for user enumeration pattern
    if paths.iter().any(|p| p.path_type == PathType::Dynamic && p.path.contains("/home/")) {
        return DirectoryAccessPattern::UserEnumeration;
    }

    // Check for batch operations (all same operation)
    let access_types: std::collections::HashSet<_> = paths
        .iter()
        .filter_map(|p| p.access_type.as_ref())
        .collect();

    if access_types.len() == 1 && files.len() > 2 {
        let op_type = access_types.iter().next().unwrap();
        return DirectoryAccessPattern::BatchOperation {
            operation: format!("{:?}", op_type),
            count: files.len(),
        };
    }

    DirectoryAccessPattern::MultipleSpecific {
        count: files.len(),
    }
}

/// Generate traits from path patterns
pub fn generate_traits_from_paths(paths: &[PathInfo]) -> Vec<Trait> {
    let mut traits = Vec::new();

    // Platform detection from paths
    traits.extend(detect_platform_from_paths(paths));

    // Anomalous path detection
    traits.extend(detect_anomalous_paths(paths));

    // Privilege requirements
    traits.extend(detect_privilege_requirements(paths));

    traits
}

/// Detect platform based on path patterns
fn detect_platform_from_paths(paths: &[PathInfo]) -> Vec<Trait> {
    let mut traits = Vec::new();

    // IoT/Embedded detection (MTD flash)
    let mtd_paths: Vec<_> = paths
        .iter()
        .filter(|p| p.path.starts_with("/mnt/mtd/") || p.path.contains("/dev/mtd"))
        .collect();

    if mtd_paths.len() >= 2 {
        traits.push(Trait {
            id: "platform/embedded/mtd_device".to_string(),
            description: "Targets embedded device with MTD flash storage".to_string(),
            confidence: 0.9,
            criticality: Criticality::Medium,
            mbc_id: None,
            attack_id: None,
            evidence: mtd_paths
                .iter()
                .map(|p| Evidence {
                    method: "path_pattern".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
            referenced_paths: Some(mtd_paths.iter().map(|p| p.path.clone()).collect()),
            referenced_directories: None,
        });
    }

    // Android detection
    let android_paths: Vec<_> = paths
        .iter()
        .filter(|p| {
            p.path.starts_with("/system/") ||
            p.path.starts_with("/data/data/") ||
            p.path.contains("/apex/")
        })
        .collect();

    if android_paths.len() >= 3 {
        traits.push(Trait {
            id: "platform/mobile/android".to_string(),
            description: "Android platform-specific paths detected".to_string(),
            confidence: 0.95,
            criticality: Criticality::Low,
            mbc_id: None,
            attack_id: None,
            evidence: android_paths
                .iter()
                .map(|p| Evidence {
                    method: "path_pattern".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
            referenced_paths: Some(android_paths.iter().map(|p| p.path.clone()).collect()),
            referenced_directories: None,
        });
    }

    traits
}

/// Detect anomalous paths (hidden files in system directories, etc.)
fn detect_anomalous_paths(paths: &[PathInfo]) -> Vec<Trait> {
    let mut traits = Vec::new();

    // Hidden files in system directories
    let anomalous_hidden: Vec<_> = paths
        .iter()
        .filter(|p| {
            p.category == PathCategory::Hidden &&
            (p.path.starts_with("/var/") || p.path.starts_with("/usr/"))
        })
        .collect();

    for path in anomalous_hidden {
        traits.push(Trait {
            id: "persistence/hidden_file".to_string(),
            description: format!("Hidden file in system directory: {}", path.path),
            confidence: 0.8,
            criticality: Criticality::High,
            mbc_id: None,
            attack_id: Some("T1564.001".to_string()), // Hide Artifacts: Hidden Files
            evidence: vec![Evidence {
                method: "path_anomaly".to_string(),
                source: path.source.clone(),
                value: path.path.clone(),
                location: None,
            }],
            referenced_paths: Some(vec![path.path.clone()]),
            referenced_directories: None,
        });
    }

    traits
}

/// Detect privilege requirements from paths
fn detect_privilege_requirements(paths: &[PathInfo]) -> Vec<Trait> {
    let mut traits = Vec::new();

    // Root-only paths
    let root_paths = [
        "/etc/shadow",
        "/proc/*/mem",
        "/dev/kmem",
        "/boot/",
        "/sys/kernel/",
    ];

    let requires_root: Vec<_> = paths
        .iter()
        .filter(|p| root_paths.iter().any(|rp| p.path.starts_with(rp)))
        .collect();

    if !requires_root.is_empty() {
        traits.push(Trait {
            id: "requires/root_access".to_string(),
            description: "Requires root privileges to access protected paths".to_string(),
            confidence: 1.0,
            criticality: Criticality::High,
            mbc_id: None,
            attack_id: None,
            evidence: requires_root
                .iter()
                .map(|p| Evidence {
                    method: "path_privilege".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
            referenced_paths: Some(requires_root.iter().map(|p| p.path.clone()).collect()),
            referenced_directories: None,
        });
    }

    traits
}

/// Generate traits from directory patterns
pub fn generate_traits_from_directories(directories: &[DirectoryAccess]) -> Vec<Trait> {
    let mut traits = Vec::new();

    for dir in directories {
        // Credential file access patterns
        if dir.directory.contains("Config") || dir.directory.contains("/etc/") {
            let cred_files: Vec<_> = dir
                .files
                .iter()
                .filter(|f| {
                    f.to_lowercase().contains("account") ||
                    f.to_lowercase().contains("passwd") ||
                    f.to_lowercase().contains("password") ||
                    f.to_lowercase().contains("credential")
                })
                .collect();

            if cred_files.len() >= 2 {
                traits.push(Trait {
                    id: "credential/backdoor/config_directory".to_string(),
                    description: format!(
                        "Systematically accesses {} credential files in {}",
                        cred_files.len(),
                        dir.directory
                    ),
                    confidence: 0.95,
                    criticality: Criticality::High,
                    mbc_id: None,
                    attack_id: Some("T1552".to_string()), // Unsecured Credentials
                    evidence: vec![Evidence {
                        method: "directory_pattern".to_string(),
                        source: "path_mapper".to_string(),
                        value: format!("{} credential files in {}", cred_files.len(), dir.directory),
                        location: None,
                    }],
                    referenced_paths: Some(cred_files
                        .iter()
                        .map(|f| format!("{}{}", dir.directory, f))
                        .collect()),
                    referenced_directories: Some(vec![dir.directory.clone()]),
                });
            }
        }

        // Log file access (potential cleanup)
        if dir.categories.contains(&PathCategory::Log) && dir.file_count >= 2 {
            traits.push(Trait {
                id: "evasion/logging/system_logs".to_string(),
                description: format!(
                    "Accesses {} log files in {} (potential cleanup)",
                    dir.file_count,
                    dir.directory
                ),
                confidence: 0.7,
                criticality: Criticality::Medium,
                mbc_id: None,
                attack_id: Some("T1070.002".to_string()), // Clear Linux Logs
                evidence: vec![Evidence {
                    method: "directory_pattern".to_string(),
                    source: "path_mapper".to_string(),
                    value: format!("{} log files accessed", dir.file_count),
                    location: Some(dir.directory.clone()),
                }],
                referenced_paths: Some(dir
                    .files
                    .iter()
                    .map(|f| format!("{}{}", dir.directory, f))
                    .collect()),
                referenced_directories: Some(vec![dir.directory.clone()]),
            });
        }
    }

    traits
}

/// Main entry point: analyze paths and link to traits
pub fn analyze_and_link_paths(report: &mut AnalysisReport) {
    // Step 1: Extract paths from strings
    let mut paths = extract_paths_from_strings(&report.strings);

    // Step 2: Group into directories
    let directories = group_into_directories(&paths);

    // Step 3: Generate traits from patterns
    let mut new_traits = Vec::new();

    // Generate traits from individual paths
    new_traits.extend(generate_traits_from_paths(&paths));

    // Generate traits from directory patterns
    new_traits.extend(generate_traits_from_directories(&directories));

    // Step 4: Add back-references
    for trait_obj in &new_traits {
        // Mark paths that contributed to this trait
        for path in &mut paths {
            if let Some(ref_paths) = &trait_obj.referenced_paths {
                if ref_paths.contains(&path.path) {
                    path.referenced_by_traits.push(trait_obj.id.clone());
                }
            }
        }
    }

    // Step 5: Update directories with generated trait IDs
    let mut updated_directories = directories;
    for dir in &mut updated_directories {
        for trait_obj in &new_traits {
            if let Some(ref_dirs) = &trait_obj.referenced_directories {
                if ref_dirs.contains(&dir.directory) {
                    dir.generated_traits.push(trait_obj.id.clone());
                }
            }
        }
    }

    // Store results
    report.paths = paths;
    report.directories = updated_directories;
    report.traits.extend(new_traits);
}
