// Migrated from malcontent: process/groups-set.yara

rule setgroups {
  meta:
    description = "set group access list"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "setgroups"
    pledge      = "id"

  strings:
$ref = "setgroups" fullword
    $go  = "_syscall.libc_setgroups_trampoline"
  condition:
    $ref and not $go
}
