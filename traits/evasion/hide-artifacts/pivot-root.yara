// Migrated from malcontent: evasion/hide_artifacts/pivot_root.yara

rule pivot_root: medium {
  meta:
    description = "change the root mount location"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "pivot_root"

  strings:
$ref       = "pivot_root" fullword
    $not_pivot = "no_pivot_root"
  condition:
    $ref and none of ($not*)
}
