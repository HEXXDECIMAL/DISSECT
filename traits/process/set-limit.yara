// Migrated from malcontent: process/limit-set.yara

rule setrlimit: harmless {
  meta:
    description = "set resource limits"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "setrlimit"
    pledge      = "id"

  strings:
$ref = "setrlimit" fullword
  condition:
    any of them
}
