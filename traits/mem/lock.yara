// Migrated from malcontent: mem/lock.yara

rule mlock: harmless {
  meta:
    description = "lock a processes virtual address space"
    confidence  = "0.66"
    pledge      = "wpath"
    syscall     = "mlock"
    capability  = "CAP_IPC_LOCK"

  strings:
$ref  = "mlock" fullword
    $ref2 = "mlock2" fullword
    $ref3 = "mlockall" fullword
  condition:
    any of them
}
