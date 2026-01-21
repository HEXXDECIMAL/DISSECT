// Migrated from malcontent: evasion/hijack_execution/LD_LIBRARY_PATH.yara

rule ld_library_path {
  meta:
    confidence  = "0.66"

  strings:
$ref = "LD_LIBRARY_PATH" fullword
  condition:
    any of them
}
