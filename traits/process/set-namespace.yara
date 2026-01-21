// Migrated from malcontent: process/namespace-set.yara

rule setns {
  meta:
    description = "associate thread or process with a namespace"
    confidence  = "0.66"
    capability  = "CAP_SYS_ADMIN"
    syscall     = "setns"

  strings:
$ref = "setns" fullword
  condition:
    any of them
}
