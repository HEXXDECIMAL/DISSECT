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
    if path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/lib/")
        || path.starts_with("/usr/lib/")
    {
        return PathCategory::System;
    }

    // Config paths
    if path.starts_with("/etc/")
        || path.ends_with(".conf")
        || path.contains("/.config/")
        || path.contains("/Config/")
    {
        return PathCategory::Config;
    }

    // Temp paths
    if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/") {
        return PathCategory::Temp;
    }

    // Log paths
    if path.starts_with("/var/log/") || path.ends_with(".log") {
        return PathCategory::Log;
    }

    // Home paths
    if path.starts_with("/home/")
        || path.starts_with("~/")
        || path == "$HOME"
        || path.contains("${HOME}")
    {
        return PathCategory::Home;
    }

    // Device/mount paths
    if path.starts_with("/dev/")
        || path.starts_with("/mnt/")
        || path.starts_with("/proc/")
        || path.starts_with("/sys/")
    {
        return PathCategory::Device;
    }

    // Runtime paths
    if path.starts_with("/var/run/") || path.starts_with("/run/") {
        return PathCategory::Runtime;
    }

    // Network config
    if path == "/etc/hosts"
        || path == "/etc/resolv.conf"
        || path == "/etc/hostname"
        || path.starts_with("/etc/network/")
    {
        return PathCategory::Network;
    }

    PathCategory::Other
}

/// Group paths by directory
pub fn group_into_directories(paths: &[PathInfo]) -> Vec<DirectoryAccess> {
    let mut dir_map: HashMap<String, Vec<&PathInfo>> = HashMap::new();

    // Group paths by directory
    for path_info in paths {
        if let Some(parent) = parent_directory(&path_info.path) {
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
fn parent_directory(path: &str) -> Option<String> {
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
    if paths
        .iter()
        .any(|p| p.path_type == PathType::Dynamic && p.path.contains("/home/"))
    {
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

    DirectoryAccessPattern::MultipleSpecific { count: files.len() }
}

/// Generate traits from path patterns
pub fn generate_traits_from_paths(paths: &[PathInfo]) -> Vec<Finding> {
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
fn detect_platform_from_paths(paths: &[PathInfo]) -> Vec<Finding> {
    let mut traits = Vec::new();

    // IoT/Embedded detection (MTD flash)
    let mtd_paths: Vec<_> = paths
        .iter()
        .filter(|p| p.path.starts_with("/mnt/mtd/") || p.path.contains("/dev/mtd"))
        .collect();

    if mtd_paths.len() >= 2 {
        traits.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "platform/embedded/mtd_device".to_string(),
            desc: "Targets embedded device with MTD flash storage".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: mtd_paths
                .iter()
                .map(|p| Evidence {
                    method: "path_pattern".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
        });
    }

    // Android detection
    let android_paths: Vec<_> = paths
        .iter()
        .filter(|p| {
            p.path.starts_with("/system/")
                || p.path.starts_with("/data/data/")
                || p.path.contains("/apex/")
        })
        .collect();

    if android_paths.len() >= 3 {
        traits.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "platform/mobile/android".to_string(),
            desc: "Android platform-specific paths detected".to_string(),
            conf: 0.95,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: android_paths
                .iter()
                .map(|p| Evidence {
                    method: "path_pattern".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
        });
    }

    traits
}

/// Detect anomalous paths (hidden files in system directories, etc.)
fn detect_anomalous_paths(paths: &[PathInfo]) -> Vec<Finding> {
    let mut traits = Vec::new();

    // Hidden files in system directories
    let anomalous_hidden: Vec<_> = paths
        .iter()
        .filter(|p| {
            p.category == PathCategory::Hidden
                && (p.path.starts_with("/var/") || p.path.starts_with("/usr/"))
        })
        .collect();

    for path in anomalous_hidden {
        traits.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "persistence/hidden_file".to_string(),
            desc: format!("Hidden file in system directory: {}", path.path),
            conf: 0.8,
            crit: Criticality::Hostile,
            mbc: None,
            attack: Some("T1564.001".to_string()), // Hide Artifacts: Hidden Files
            evidence: vec![Evidence {
                method: "path_anomaly".to_string(),
                source: path.source.clone(),
                value: path.path.clone(),
                location: None,
            }],
        });
    }

    traits
}

/// Detect privilege requirements from paths
fn detect_privilege_requirements(paths: &[PathInfo]) -> Vec<Finding> {
    let mut traits = Vec::new();

    // Root-only paths
    // NOTE: /sys/kernel/ is too broad - Go runtime reads /sys/kernel/mm/transparent_hugepage/
    // for memory optimization. Only flag specific sensitive paths.
    let root_paths = [
        "/etc/shadow",
        "/proc/*/mem",
        "/dev/kmem",
        "/boot/vmlinuz",
        "/boot/initrd",
        "/sys/kernel/debug/",
        "/sys/kernel/security/",
    ];

    let requires_root: Vec<_> = paths
        .iter()
        .filter(|p| root_paths.iter().any(|rp| p.path.starts_with(rp)))
        .collect();

    if !requires_root.is_empty() {
        traits.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "os/privilege/root-access".to_string(),
            desc: "Accesses paths that typically require root privileges".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: requires_root
                .iter()
                .map(|p| Evidence {
                    method: "path_privilege".to_string(),
                    source: p.source.clone(),
                    value: p.path.clone(),
                    location: None,
                })
                .collect(),
        });
    }

    traits
}

/// Generate traits from directory patterns
pub fn generate_traits_from_directories(directories: &[DirectoryAccess]) -> Vec<Finding> {
    let mut traits = Vec::new();

    for dir in directories {
        // Credential file access patterns
        if dir.directory.contains("Config") || dir.directory.contains("/etc/") {
            let cred_files: Vec<_> = dir
                .files
                .iter()
                .filter(|f| {
                    f.to_lowercase().contains("account")
                        || f.to_lowercase().contains("passwd")
                        || f.to_lowercase().contains("password")
                        || f.to_lowercase().contains("credential")
                })
                .collect();

            if cred_files.len() >= 2 {
                traits.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "credential/backdoor/config_directory".to_string(),
                    desc: format!(
                        "Systematically accesses {} credential files in {}",
                        cred_files.len(),
                        dir.directory
                    ),
                    conf: 0.95,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: Some("T1552".to_string()), // Unsecured Credentials
                    evidence: vec![Evidence {
                        method: "directory_pattern".to_string(),
                        source: "path_mapper".to_string(),
                        value: format!(
                            "{} credential files in {}",
                            cred_files.len(),
                            dir.directory
                        ),
                        location: None,
                    }],
                });
            }
        }

        // Log file access (potential cleanup)
        if dir.categories.contains(&PathCategory::Log) && dir.file_count >= 2 {
            traits.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "evasion/logging/system_logs".to_string(),
                desc: format!(
                    "Accesses {} log files in {} (potential cleanup)",
                    dir.file_count, dir.directory
                ),
                conf: 0.7,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: Some("T1070.002".to_string()), // Clear Linux Logs
                evidence: vec![Evidence {
                    method: "directory_pattern".to_string(),
                    source: "path_mapper".to_string(),
                    value: format!("{} log files accessed", dir.file_count),
                    location: Some(dir.directory.clone()),
                }],
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

    // Step 4: Add back-references using evidence
    for trait_obj in &new_traits {
        // Mark paths that contributed to this trait based on evidence
        for path in &mut paths {
            if trait_obj.evidence.iter().any(|e| e.value == path.path) {
                path.referenced_by_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Step 5: Update directories with generated trait IDs
    let mut updated_directories = directories;
    for dir in &mut updated_directories {
        for trait_obj in &new_traits {
            if trait_obj
                .evidence
                .iter()
                .any(|e| e.location.as_ref() == Some(&dir.directory))
            {
                dir.generated_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Store results
    report.paths = paths;
    report.directories = updated_directories;
    report.findings.extend(new_traits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_path_type_absolute() {
        assert_eq!(classify_path_type("/etc/passwd"), PathType::Absolute);
        assert_eq!(classify_path_type("/bin/sh"), PathType::Absolute);
        assert_eq!(classify_path_type("/home/user/.bashrc"), PathType::Absolute);
    }

    #[test]
    fn test_classify_path_type_relative() {
        assert_eq!(classify_path_type("./file.txt"), PathType::Relative);
        assert_eq!(classify_path_type("../config"), PathType::Relative);
        assert_eq!(classify_path_type("foo/../bar"), PathType::Relative);
    }

    #[test]
    fn test_classify_path_type_dynamic() {
        assert_eq!(classify_path_type("/home/%s/.config"), PathType::Dynamic);
        assert_eq!(classify_path_type("/tmp/file-%d"), PathType::Dynamic);
        assert_eq!(classify_path_type("${HOME}/.bashrc"), PathType::Dynamic);
        assert_eq!(classify_path_type("$HOME/.profile"), PathType::Dynamic);
    }

    #[test]
    fn test_classify_path_category_system() {
        assert_eq!(classify_path_category("/bin/bash"), PathCategory::System);
        assert_eq!(classify_path_category("/sbin/init"), PathCategory::System);
        assert_eq!(
            classify_path_category("/usr/bin/python"),
            PathCategory::System
        );
        assert_eq!(classify_path_category("/lib/libc.so"), PathCategory::System);
    }

    #[test]
    fn test_classify_path_category_config() {
        assert_eq!(classify_path_category("/etc/passwd"), PathCategory::Config);
        assert_eq!(classify_path_category("/etc/hosts"), PathCategory::Config);
        assert_eq!(classify_path_category("app.conf"), PathCategory::Config);
        // Note: /home/user/.config/app is classified as Hidden due to the dot
    }

    #[test]
    fn test_classify_path_category_temp() {
        assert_eq!(classify_path_category("/tmp/file"), PathCategory::Temp);
        assert_eq!(classify_path_category("/var/tmp/data"), PathCategory::Temp);
        assert_eq!(
            classify_path_category("/dev/shm/buffer"),
            PathCategory::Temp
        );
    }

    #[test]
    fn test_classify_path_category_log() {
        assert_eq!(classify_path_category("/var/log/syslog"), PathCategory::Log);
        assert_eq!(classify_path_category("app.log"), PathCategory::Log);
    }

    #[test]
    fn test_classify_path_category_home() {
        assert_eq!(
            classify_path_category("/home/user/file"),
            PathCategory::Home
        );
        // Note: ~ and $HOME are classified as Dynamic, not Home
    }

    #[test]
    fn test_classify_path_category_device() {
        assert_eq!(classify_path_category("/dev/null"), PathCategory::Device);
        assert_eq!(
            classify_path_category("/proc/self/maps"),
            PathCategory::Device
        );
        assert_eq!(
            classify_path_category("/sys/class/net"),
            PathCategory::Device
        );
    }

    #[test]
    fn test_classify_path_category_runtime() {
        assert_eq!(
            classify_path_category("/var/run/app.pid"),
            PathCategory::Runtime
        );
        assert_eq!(
            classify_path_category("/run/lock/file"),
            PathCategory::Runtime
        );
    }

    #[test]
    fn test_classify_path_category_hidden() {
        assert_eq!(classify_path_category(".hidden"), PathCategory::Hidden);
        assert_eq!(
            classify_path_category("/path/.hidden"),
            PathCategory::Hidden
        );
    }

    #[test]
    fn test_parent_directory() {
        assert_eq!(parent_directory("/etc/passwd"), Some("/etc/".to_string()));
        assert_eq!(
            parent_directory("/etc/network/interfaces"),
            Some("/etc/network/".to_string())
        );
        assert_eq!(parent_directory("/etc"), Some("/".to_string()));
        assert_eq!(parent_directory("file.txt"), None);
    }

    #[test]
    fn test_extract_paths_from_strings() {
        let strings = vec![
            StringInfo {
                value: "/etc/passwd".to_string(),
                string_type: StringType::Path,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
            },
            StringInfo {
                value: "/bin/sh".to_string(),
                string_type: StringType::Path,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
            },
            StringInfo {
                value: "not a path".to_string(),
                string_type: StringType::Plain,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
            },
        ];

        let paths = extract_paths_from_strings(&strings);

        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| p.path == "/etc/passwd"));
        assert!(paths.iter().any(|p| p.path == "/bin/sh"));
    }

    #[test]
    fn test_analyze_path() {
        let path_info = analyze_path("/etc/passwd", "strings");

        assert_eq!(path_info.path, "/etc/passwd");
        assert_eq!(path_info.path_type, PathType::Absolute);
        assert_eq!(path_info.category, PathCategory::Config);
        assert_eq!(path_info.source, "strings");
        assert!(!path_info.evidence.is_empty());
    }

    #[test]
    fn test_detect_platform_from_paths_mtd() {
        let paths = vec![
            PathInfo {
                path: "/mnt/mtd/config".to_string(),
                path_type: PathType::Absolute,
                category: PathCategory::Other,
                access_type: None,
                source: "strings".to_string(),
                evidence: vec![],
                referenced_by_traits: vec![],
            },
            PathInfo {
                path: "/dev/mtdblock0".to_string(),
                path_type: PathType::Absolute,
                category: PathCategory::Device,
                access_type: None,
                source: "strings".to_string(),
                evidence: vec![],
                referenced_by_traits: vec![],
            },
        ];

        let traits = detect_platform_from_paths(&paths);

        assert!(traits
            .iter()
            .any(|t| t.id.contains("embedded") && t.id.contains("mtd")));
    }

    #[test]
    fn test_detect_privilege_requirements() {
        let paths = vec![PathInfo {
            path: "/etc/shadow".to_string(),
            path_type: PathType::Absolute,
            category: PathCategory::Config,
            access_type: None,
            source: "strings".to_string(),
            evidence: vec![],
            referenced_by_traits: vec![],
        }];

        let traits = detect_privilege_requirements(&paths);

        assert!(traits.iter().any(|t| t.id.contains("root-access")));
    }
}
