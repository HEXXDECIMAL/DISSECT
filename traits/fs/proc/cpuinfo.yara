// Migrated from malcontent: fs/proc/cpuinfo.yara

rule proc_cpuinfo: medium {
  meta:
    description = "get CPU info"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/proc/cpuinfo" fullword
  condition:
    any of them
}
