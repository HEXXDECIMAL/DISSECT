// Migrated from malcontent: discover/process/priority.yara

rule getpriority: harmless {
  meta:
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    syscall     = "getpriority"
    pledge      = "proc"

  strings:
$ref = "getpriority" fullword
  condition:
    any of them
}
