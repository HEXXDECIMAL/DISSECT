// Migrated from malcontent: fs/proc/self-exe.yara

rule proc_self_exe: medium {
  meta:
    description = "gets executable associated to this process"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "stdio"

  strings:
$ref = "/proc/self/exe" fullword
  condition:
    any of them
}
