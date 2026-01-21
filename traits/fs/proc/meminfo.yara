// Migrated from malcontent: fs/proc/meminfo.yara

rule proc_meminfo_val: medium {
  meta:
    description = "get memory info"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/proc/meminfo" fullword
  condition:
    any of them
}
