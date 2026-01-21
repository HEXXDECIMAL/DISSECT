// Migrated from malcontent: process/setpriority.yara

rule nice: harmless {
  meta:
    description = "adjust the process nice value"
    confidence  = "0.66"
    capability  = "CAP_SYS_NICE"
    syscall     = "nice"

  strings:
$ref  = "nice" fullword
    $ref2 = "renice" fullword
  condition:
    any of them
}

rule setpriority: harmless {
  meta:
    description = "adjust the process nice value"
    confidence  = "0.66"
    capability  = "CAP_SYS_NICE"
    syscall     = "setpriority"

  strings:
$ref = "setpriority" fullword
  condition:
    any of them
}
