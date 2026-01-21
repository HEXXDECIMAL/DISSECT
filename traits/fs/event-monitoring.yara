// Migrated from malcontent: fs/event-monitoring.yara

rule syscall_fanotify_init: linux {
  meta:
    description = "filesystem event monitoring"
    confidence  = "0.66"
    syscall     = "fanotify_init"
    capability  = "CAP_SYS_ADMBIN"

  strings:
$ref = "fanotify_init"
  condition:
    any of them
}
