// Migrated from malcontent: discover/process/resource-limits.yara

rule getrlimit: harmless {
  meta:
    description = "retrieve resource limits"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    syscall     = "getrlimit"
    pledge      = "id"

  strings:
$ref = "getrlimit" fullword
    $go  = "Getrlimit" fullword
  condition:
    any of them
}
