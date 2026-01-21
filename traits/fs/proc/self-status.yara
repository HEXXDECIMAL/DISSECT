// Migrated from malcontent: fs/proc/self-status.yara

rule proc_self_status: medium {
  meta:
    description = "gets status associated to this process, including capabilities"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "stdio"

  strings:
$ref = "/proc/self/status" fullword
  condition:
    any of them
}
