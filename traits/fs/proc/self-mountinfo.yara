// Migrated from malcontent: fs/proc/self-mountinfo.yara

rule proc_self_mountinfo: medium {
  meta:
    description = "gets mount info associated to this process"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "stdio"

  strings:
$ref = "/proc/self/mountinfo"
  condition:
    $ref
}
