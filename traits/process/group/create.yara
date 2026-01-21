// Migrated from malcontent: process/group/create.yara

rule syscalls: harmless {
  meta:
    description = "creates a session and sets the process group ID"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "proc"
    syscall     = "setsid"
    ref         = "https://man7.org/linux/man-pages/man2/setsid.2.html"

  strings:
$setsid = "setsid" fullword
  condition:
    any of them
}
