// Migrated from malcontent: os/signal/group-send.yara

rule killpg: harmless {
  meta:
    confidence  = "0.66"
    syscall     = "kill"
    pledge      = "proc"

  strings:
$kill = "_killpg" fullword
  condition:
    any of them
}
