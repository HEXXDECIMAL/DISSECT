use crate::types::*;

/// Extract environment variable access from strings and categorize them
pub fn extract_envvars_from_strings(strings: &[StringInfo]) -> Vec<EnvVarInfo> {
    let mut env_vars = Vec::new();

    for string_info in strings {
        // Look for common environment variable names in strings
        if is_env_var_name(&string_info.value) {
            let env_var_info =
                analyze_env_var(&string_info.value, "strings", EnvVarAccessType::Unknown);
            env_vars.push(env_var_info);
        }
    }

    env_vars
}

/// Extract environment variables from function calls (getenv, setenv, etc.)
pub fn extract_envvars_from_imports(imports: &[Import]) -> Vec<(String, EnvVarAccessType)> {
    let mut env_api_calls = Vec::new();

    for import in imports {
        let symbol = import.symbol.as_str();

        // Unix/Linux API calls
        if symbol.contains("getenv") || symbol == "getenv" {
            env_api_calls.push(("getenv".to_string(), EnvVarAccessType::Read));
        } else if symbol.contains("setenv") || symbol == "setenv" {
            env_api_calls.push(("setenv".to_string(), EnvVarAccessType::Write));
        } else if symbol.contains("putenv") || symbol == "putenv" {
            env_api_calls.push(("putenv".to_string(), EnvVarAccessType::Write));
        } else if symbol.contains("unsetenv") || symbol == "unsetenv" {
            env_api_calls.push(("unsetenv".to_string(), EnvVarAccessType::Delete));
        }
        // Windows API calls
        else if symbol.contains("GetEnvironmentVariable") {
            env_api_calls.push(("GetEnvironmentVariable".to_string(), EnvVarAccessType::Read));
        } else if symbol.contains("SetEnvironmentVariable") {
            env_api_calls.push((
                "SetEnvironmentVariable".to_string(),
                EnvVarAccessType::Write,
            ));
        }
    }

    env_api_calls
}

/// Check if string looks like an environment variable name
fn is_env_var_name(s: &str) -> bool {
    // Must be uppercase letters, numbers, and underscores
    if s.is_empty() || s.len() > 100 {
        return false;
    }

    // Must be all uppercase with underscores or numbers
    let valid_chars = s
        .chars()
        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit());
    if !valid_chars {
        return false;
    }

    // Must not start with a digit
    if s.chars().next().unwrap().is_ascii_digit() {
        return false;
    }

    // Check against known environment variables
    is_known_env_var(s)
}

/// Check if this is a known environment variable name
fn is_known_env_var(name: &str) -> bool {
    matches!(
        name,
        // Common system vars
        "PATH" | "HOME" | "USER" | "USERNAME" | "SHELL" | "TERM" | "HOSTNAME" |
        "PWD" | "OLDPWD" | "LOGNAME" | "DISPLAY" | "LANG" |

        // Temporary directories
        "TEMP" | "TMP" | "TMPDIR" | "TEMPDIR" |

        // Windows-specific
        "USERPROFILE" | "APPDATA" | "LOCALAPPDATA" | "PROGRAMFILES" |
        "SYSTEMROOT" | "WINDIR" | "COMSPEC" | "HOMEDRIVE" | "HOMEPATH" |

        // Runtime paths
        "LD_LIBRARY_PATH" | "LD_PRELOAD" | "DYLD_LIBRARY_PATH" |
        "DYLD_INSERT_LIBRARIES" | "DYLD_FORCE_FLAT_NAMESPACE" |
        "PYTHONPATH" | "PYTHONHOME" | "NODE_PATH" | "RUBYLIB" | "GOPATH" | "CLASSPATH" |

        // Platform-specific
        "ANDROID_ROOT" | "ANDROID_DATA" | "ANDROID_STORAGE" |

        // Network/proxy
        "http_proxy" | "https_proxy" | "HTTP_PROXY" | "HTTPS_PROXY" | "no_proxy" | "NO_PROXY" |
        "FTP_PROXY" | "ftp_proxy" | "ALL_PROXY" | "all_proxy" |

        // Editor/pager
        "EDITOR" | "VISUAL" | "PAGER" |

        // SSH
        "SSH_AUTH_SOCK" | "SSH_AGENT_PID" | "SSH_CONNECTION" | "SSH_CLIENT" | "SSH_TTY" |

        // Locale
        "LC_ALL" | "LC_CTYPE" | "LC_COLLATE" | "LC_TIME" | "LC_NUMERIC" |
        "LC_MONETARY" | "LC_MESSAGES" | "LANGUAGE"
    ) || name.starts_with("LC_") ||  // Locale variables
        name.ends_with("_TOKEN") ||   // API tokens
        name.ends_with("_KEY") ||     // API keys
        name.ends_with("_SECRET") ||  // Secrets
        name.ends_with("_PASSWORD") || // Passwords
        name.starts_with("AWS_") ||   // AWS credentials
        name.starts_with("GITHUB_") || // GitHub tokens
        name.starts_with("DOCKER_") || // Docker config
        name.starts_with("KUBERNETES_") || // K8s config
        name.starts_with("CI_") ||    // CI/CD variables
        name.starts_with("JENKINS_") || // Jenkins
        name.starts_with("TRAVIS_") || // Travis CI
        name.starts_with("GITLAB_") || // GitLab CI
        name.starts_with("ANDROID_") // Android platform
}

/// Analyze a single environment variable and categorize it
fn analyze_env_var(name: &str, source: &str, access_type: EnvVarAccessType) -> EnvVarInfo {
    let category = classify_env_var_category(name);

    EnvVarInfo {
        name: name.to_string(),
        access_type,
        source: source.to_string(),
        category,
        evidence: vec![Evidence {
            method: "string_pattern".to_string(),
            source: source.to_string(),
            value: name.to_string(),
            location: None,
        }],
        referenced_by_traits: Vec::new(),
    }
}

/// Classify environment variable by semantic category
fn classify_env_var_category(name: &str) -> EnvVarCategory {
    // Credential/secret detection (highest priority)
    if name.ends_with("_TOKEN")
        || name.ends_with("_KEY")
        || name.ends_with("_SECRET")
        || name.ends_with("_PASSWORD")
        || name.starts_with("AWS_")
        || name.starts_with("GITHUB_")
        || name.contains("API_KEY")
        || name.contains("ACCESS_TOKEN")
    {
        return EnvVarCategory::Credential;
    }

    // Injection/evasion
    if name == "LD_PRELOAD"
        || name == "DYLD_INSERT_LIBRARIES"
        || name == "DYLD_FORCE_FLAT_NAMESPACE"
    {
        return EnvVarCategory::Injection;
    }

    // Path-related
    if name == "PATH"
        || name == "LD_LIBRARY_PATH"
        || name == "DYLD_LIBRARY_PATH"
        || name == "PYTHONPATH"
        || name == "NODE_PATH"
        || name == "RUBYLIB"
        || name == "GOPATH"
        || name == "CLASSPATH"
    {
        return EnvVarCategory::Path;
    }

    // User information
    if name == "USER"
        || name == "USERNAME"
        || name == "LOGNAME"
        || name == "HOME"
        || name == "USERPROFILE"
        || name == "HOMEDRIVE"
        || name == "HOMEPATH"
    {
        return EnvVarCategory::User;
    }

    // System information
    if name == "HOSTNAME"
        || name == "SHELL"
        || name == "TERM"
        || name == "PWD"
        || name == "OLDPWD"
        || name == "SYSTEMROOT"
        || name == "WINDIR"
    {
        return EnvVarCategory::System;
    }

    // Temporary directories
    if name == "TEMP" || name == "TMP" || name == "TMPDIR" || name == "TEMPDIR" {
        return EnvVarCategory::Temp;
    }

    // Display/UI
    if name == "DISPLAY" || name.starts_with("WAYLAND_") {
        return EnvVarCategory::Display;
    }

    // Runtime paths
    if name == "PYTHONHOME"
        || name.starts_with("PYTHON")
        || name.starts_with("NODE_")
        || name.starts_with("RUBY")
        || name.starts_with("GO")
        || name == "JAVA_HOME"
    {
        return EnvVarCategory::Runtime;
    }

    // Platform-specific
    if name.starts_with("ANDROID_") || name.starts_with("IOS_") {
        return EnvVarCategory::Platform;
    }

    // Locale
    if name == "LANG" || name == "LANGUAGE" || name.starts_with("LC_") {
        return EnvVarCategory::Locale;
    }

    // Network/proxy
    if name.contains("proxy") || name.contains("PROXY") {
        return EnvVarCategory::Network;
    }

    EnvVarCategory::Other
}

/// Generate traits from environment variable patterns
pub fn generate_traits_from_env_vars(env_vars: &[EnvVarInfo]) -> Vec<Trait> {
    let mut traits = Vec::new();

    // Credential access detection
    let credential_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.category == EnvVarCategory::Credential)
        .collect();

    if !credential_vars.is_empty() {
        traits.push(Trait {
            id: "credential/env/access".to_string(),
            description: format!(
                "Accesses {} environment variables containing credentials/secrets",
                credential_vars.len()
            ),
            confidence: 0.95,
            criticality: Criticality::Hostile,
            capability: true,
            mbc: None,
            attack: Some("T1552.001".to_string()), // Unsecured Credentials
            evidence: credential_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // LD_PRELOAD injection detection
    let injection_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.category == EnvVarCategory::Injection)
        .collect();

    for var in injection_vars {
        let (trait_id, description, attack_id) = match var.name.as_str() {
            "LD_PRELOAD" => (
                "evasion/library/preload",
                "Uses LD_PRELOAD for library injection",
                "T1574.006", // Hijack Execution Flow: LD_PRELOAD
            ),
            "DYLD_INSERT_LIBRARIES" => (
                "evasion/library/dyld_inject",
                "Uses DYLD_INSERT_LIBRARIES for library injection on macOS",
                "T1574.006",
            ),
            _ => (
                "evasion/library/injection",
                "Library injection via environment variable",
                "T1574.006",
            ),
        };

        traits.push(Trait {
            id: trait_id.to_string(),
            description: description.to_string(),
            confidence: 0.95,
            criticality: Criticality::Hostile,
            capability: true,
            mbc: None,
            attack: Some(attack_id.to_string()),
            evidence: vec![Evidence {
                method: "env_var".to_string(),
                source: var.source.clone(),
                value: var.name.clone(),
                location: None,
            }],
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // User discovery
    let user_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.category == EnvVarCategory::User)
        .collect();

    if user_vars.len() >= 2 {
        traits.push(Trait {
            id: "discovery/env/user".to_string(),
            description: "Discovers user information via environment variables".to_string(),
            confidence: 0.8,
            criticality: Criticality::Notable,
            capability: true,
            mbc: None,
            attack: Some("T1033".to_string()), // System Owner/User Discovery
            evidence: user_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // System discovery
    let system_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.category == EnvVarCategory::System)
        .collect();

    if system_vars.len() >= 2 {
        traits.push(Trait {
            id: "discovery/env/system".to_string(),
            description: "Discovers system information via environment variables".to_string(),
            confidence: 0.8,
            criticality: Criticality::Notable,
            capability: true,
            mbc: None,
            attack: Some("T1082".to_string()), // System Information Discovery
            evidence: system_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // PATH manipulation (if write access)
    let path_write: Vec<_> = env_vars
        .iter()
        .filter(|e| e.name == "PATH" && e.access_type == EnvVarAccessType::Write)
        .collect();

    if !path_write.is_empty() {
        traits.push(Trait {
            id: "persistence/env/path_manipulation".to_string(),
            description: "Modifies PATH environment variable for persistence/hijacking".to_string(),
            confidence: 0.9,
            criticality: Criticality::Hostile,
            capability: true,
            mbc: None,
            attack: Some("T1574.007".to_string()), // Hijack Execution Flow: Path Interception
            evidence: path_write
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // Platform detection
    let android_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.name.starts_with("ANDROID_"))
        .collect();

    if !android_vars.is_empty() {
        traits.push(Trait {
            id: "platform/mobile/android_env".to_string(),
            description: "Android platform detected via environment variables".to_string(),
            confidence: 0.9,
            criticality: Criticality::Notable,
            capability: true,
            mbc: None,
            attack: None,
            evidence: android_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // Display check (VM/sandbox detection)
    let display_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.name == "DISPLAY" || e.name == "WAYLAND_DISPLAY")
        .collect();

    if !display_vars.is_empty() {
        traits.push(Trait {
            id: "anti-analysis/env/display_check".to_string(),
            description: "Checks DISPLAY variable (potential sandbox detection)".to_string(),
            confidence: 0.6,
            criticality: Criticality::Suspicious,
            capability: true,
            mbc: None,
            attack: Some("T1497".to_string()), // Virtualization/Sandbox Evasion
            evidence: display_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    // SSH check (remote session detection)
    let ssh_vars: Vec<_> = env_vars
        .iter()
        .filter(|e| e.name.starts_with("SSH_"))
        .collect();

    if !ssh_vars.is_empty() {
        traits.push(Trait {
            id: "anti-analysis/env/ssh_check".to_string(),
            description: "Checks SSH variables (remote session detection)".to_string(),
            confidence: 0.7,
            criticality: Criticality::Suspicious,
            capability: true,
            mbc: None,
            attack: Some("T1497".to_string()), // Virtualization/Sandbox Evasion
            evidence: ssh_vars
                .iter()
                .map(|e| Evidence {
                    method: "env_var".to_string(),
                    source: e.source.clone(),
                    value: e.name.clone(),
                    location: None,
                })
                .collect(),
            language: None,
            platforms: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
        });
    }

    traits
}

/// Main entry point: analyze environment variables and link to traits
pub fn analyze_and_link_env_vars(report: &mut AnalysisReport) {
    // Step 1: Start with existing env_vars (from script analyzers like Python)
    // then add env vars extracted from strings
    let mut env_vars = report.env_vars.clone();
    env_vars.extend(extract_envvars_from_strings(&report.strings));

    // Step 2: Check for API calls
    let env_api_calls = extract_envvars_from_imports(&report.imports);

    // Add traits for API usage even if we don't know which specific vars are accessed
    for (api_name, access_type) in env_api_calls {
        let trait_id = match access_type {
            EnvVarAccessType::Read => "env/api/getenv",
            EnvVarAccessType::Write => "env/api/setenv",
            EnvVarAccessType::Delete => "env/api/unsetenv",
            _ => "env/api/access",
        };

        if !report.traits.iter().any(|t| t.id == trait_id) {
            report.traits.push(Trait {
                id: trait_id.to_string(),
                description: format!("Uses {} to access environment variables", api_name),
                confidence: 1.0,
                criticality: Criticality::Inert,
                capability: true,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    source: "imports".to_string(),
                    value: api_name,
                    location: None,
                }],
                language: None,
                platforms: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
            });
        }
    }

    // Step 3: Generate behavioral traits from patterns
    let new_traits = generate_traits_from_env_vars(&env_vars);

    // Step 4: Add back-references
    for trait_obj in &new_traits {
        // Mark env vars that contributed to this trait
        for env_var in &mut env_vars {
            if trait_obj.evidence.iter().any(|e| e.value == env_var.name) {
                env_var.referenced_by_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Store results
    report.env_vars = env_vars;
    report.traits.extend(new_traits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_env_var_name() {
        assert!(is_env_var_name("PATH"));
        assert!(is_env_var_name("HOME"));

        assert!(!is_env_var_name(""));
        assert!(!is_env_var_name("a")); // Too short
        assert!(!is_env_var_name("path")); // All lowercase
    }

    #[test]
    fn test_is_known_env_var() {
        // System paths
        assert!(is_known_env_var("PATH"));
        assert!(is_known_env_var("HOME"));
        assert!(is_known_env_var("TEMP"));

        // User info
        assert!(is_known_env_var("USER"));
        assert!(is_known_env_var("USERNAME"));

        // Shell vars
        assert!(is_known_env_var("SHELL"));
        assert!(is_known_env_var("TERM"));

        // Unknown
        assert!(!is_known_env_var("MY_CUSTOM_VAR"));
    }

    #[test]
    fn test_classify_env_var_category_path() {
        assert_eq!(classify_env_var_category("PATH"), EnvVarCategory::Path);
        assert_eq!(
            classify_env_var_category("LD_LIBRARY_PATH"),
            EnvVarCategory::Path
        );
    }

    #[test]
    fn test_classify_env_var_category_user() {
        assert_eq!(classify_env_var_category("HOME"), EnvVarCategory::User);
        assert_eq!(classify_env_var_category("USER"), EnvVarCategory::User);
        assert_eq!(classify_env_var_category("USERNAME"), EnvVarCategory::User);
    }

    #[test]
    fn test_classify_env_var_category_system() {
        assert_eq!(classify_env_var_category("SHELL"), EnvVarCategory::System);
        assert_eq!(classify_env_var_category("TERM"), EnvVarCategory::System);
        assert_eq!(classify_env_var_category("PWD"), EnvVarCategory::System);
    }

    #[test]
    fn test_classify_env_var_category_temp() {
        assert_eq!(classify_env_var_category("TEMP"), EnvVarCategory::Temp);
        assert_eq!(classify_env_var_category("TMP"), EnvVarCategory::Temp);
        assert_eq!(classify_env_var_category("TMPDIR"), EnvVarCategory::Temp);
    }

    #[test]
    fn test_classify_env_var_category_locale() {
        assert_eq!(classify_env_var_category("LANG"), EnvVarCategory::Locale);
        assert_eq!(classify_env_var_category("LC_ALL"), EnvVarCategory::Locale);
        assert_eq!(
            classify_env_var_category("LANGUAGE"),
            EnvVarCategory::Locale
        );
    }

    #[test]
    fn test_classify_env_var_category_network() {
        assert_eq!(
            classify_env_var_category("HTTP_PROXY"),
            EnvVarCategory::Network
        );
        assert_eq!(
            classify_env_var_category("HTTPS_PROXY"),
            EnvVarCategory::Network
        );
        assert_eq!(
            classify_env_var_category("NO_PROXY"),
            EnvVarCategory::Network
        );
    }

    #[test]
    fn test_classify_env_var_category_other() {
        assert_eq!(
            classify_env_var_category("MY_CUSTOM_VAR"),
            EnvVarCategory::Other
        );
        assert_eq!(
            classify_env_var_category("UNKNOWN_VAR"),
            EnvVarCategory::Other
        );
    }
}
