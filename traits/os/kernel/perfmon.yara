// Migrated from malcontent: os/kernel/perfmon.yara

rule perf_event_open {
  meta:
    description = "set up performance monitoring"
    confidence  = "0.66"
    capability  = "CAP_SYS_PERFMON"

  strings:
$ref = "perf_event_open" fullword
  condition:
    any of them
}
