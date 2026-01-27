//! Path and environment variable analysis types

use serde::{Deserialize, Serialize};

use super::is_false;
use super::traits_findings::Evidence;

/// File system path discovered in binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    /// The path string as found
    pub path: String,

    /// Classification of path format
    #[serde(rename = "type")]
    pub path_type: PathType,

    /// Semantic category
    pub category: PathCategory,

    /// How the path is accessed (if determinable)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_type: Option<PathAccessType>,

    /// Where discovered (strings, yara, function_analysis)
    pub source: String,

    /// Evidence for this path
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this path (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// Path type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathType {
    /// Absolute path (/etc/passwd)
    Absolute,
    /// Relative path (../../etc/passwd)
    Relative,
    /// Dynamic path with variables (/home/%s, /tmp/file-%d, ${HOME}/.config)
    Dynamic,
}

/// Semantic category of path
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathCategory {
    /// System directories (/bin/, /sbin/, /usr/bin/)
    System,
    /// Configuration files (/etc/, *.conf, .config/)
    Config,
    /// Temporary files (/tmp/, /var/tmp/, /dev/shm/)
    Temp,
    /// Log files (/var/log/)
    Log,
    /// Home directories (/home/, ~/)
    Home,
    /// Device/mount points (/dev/, /mnt/, /proc/, /sys/)
    Device,
    /// Runtime files (/var/run/, /run/)
    Runtime,
    /// Hidden files (.* files/directories)
    Hidden,
    /// Network configuration (/etc/hosts, /etc/resolv.conf)
    Network,
    /// Other/unknown
    Other,
}

/// How a path is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathAccessType {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Unknown,
}

/// Directory with multiple file accesses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAccess {
    /// The directory path
    pub directory: String,

    /// Files within this directory (just filenames)
    pub files: Vec<String>,

    /// Number of files
    pub file_count: usize,

    /// Pattern of access
    pub access_pattern: DirectoryAccessPattern,

    /// Categories of files in this directory
    pub categories: Vec<PathCategory>,

    /// Whether directory itself was enumerated (opendir/readdir)
    #[serde(default, skip_serializing_if = "is_false")]
    pub enumerated: bool,

    /// Trait IDs generated from this directory pattern
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub generated_traits: Vec<String>,
}

/// Pattern of directory access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryAccessPattern {
    /// Single hardcoded file
    SingleFile,

    /// Multiple specific files (hardcoded list)
    MultipleSpecific { count: usize },

    /// Directory enumeration (opendir/readdir/glob)
    Enumeration { pattern: Option<String> },

    /// Batch operations (multiple files, same operation)
    BatchOperation { operation: String, count: usize },

    /// User enumeration (/home/* pattern)
    UserEnumeration,
}

/// Environment variable discovered in binary or script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarInfo {
    /// Environment variable name (e.g., "PATH", "HOME")
    pub name: String,

    /// How the env var is accessed
    pub access_type: EnvVarAccessType,

    /// Where discovered (getenv, setenv, strings, ast)
    pub source: String,

    /// Semantic category
    pub category: EnvVarCategory,

    /// Evidence for this environment variable access
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this env var (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// How environment variable is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarAccessType {
    /// Reading variable value (getenv)
    Read,
    /// Setting variable value (setenv, putenv)
    Write,
    /// Removing variable (unsetenv)
    Delete,
    /// Unknown access type
    Unknown,
}

/// Semantic category of environment variable
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarCategory {
    /// System paths (PATH, LD_LIBRARY_PATH, PYTHONPATH)
    Path,
    /// User information (USER, USERNAME, HOME, USERPROFILE)
    User,
    /// System information (HOSTNAME, SHELL, TERM)
    System,
    /// Temporary directories (TEMP, TMP, TMPDIR)
    Temp,
    /// Display/UI (DISPLAY, WAYLAND_DISPLAY)
    Display,
    /// Security/credentials (API_KEY, TOKEN, PASSWORD, AWS_*, GITHUB_TOKEN)
    Credential,
    /// Language runtimes (PYTHONPATH, NODE_PATH, RUBYLIB, GOPATH)
    Runtime,
    /// Platform-specific (ANDROID_*, IOS_*)
    Platform,
    /// Injection/evasion (LD_PRELOAD, DYLD_INSERT_LIBRARIES)
    Injection,
    /// Locale/language (LANG, LC_*, LANGUAGE)
    Locale,
    /// Network (http_proxy, https_proxy, no_proxy)
    Network,
    /// Other/unknown
    Other,
}
