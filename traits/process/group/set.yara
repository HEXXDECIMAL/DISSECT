// Migrated from malcontent: process/group/set.yara

rule setpgid: harmless {
  meta:
    confidence  = "0.66"
    pledge      = "proc"
    syscall     = "setpgid"

  strings:
$setpgid = "setpgid" fullword
    $setpgrp = "setpgrp" fullword
  condition:
    any of them
}
