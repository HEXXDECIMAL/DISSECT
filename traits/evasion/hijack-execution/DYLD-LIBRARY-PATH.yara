// Migrated from malcontent: evasion/hijack_execution/DYLD_LIBRARY_PATH.yara

rule dyld_library_path: medium {
  meta:
    description = "overrides the library search path"
    confidence  = "0.66"

  strings:
$ref = "DYLD_LIBRARY_PATH"
  condition:
    any of them
}
