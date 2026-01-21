// Migrated from malcontent: mem/mprotect.yara

rule mprotect: harmless {
  meta:
    confidence  = "0.66"
    pledge      = "stdio"
    syscall     = "mprotect"

  strings:
$ref = "mprotect" fullword
  condition:
    any of them
}
