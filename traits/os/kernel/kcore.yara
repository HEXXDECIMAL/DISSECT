// Migrated from malcontent: os/kernel/kcore.yara

rule kcore: unusual {
  meta:
    description = "access physical memory of the system in core file format"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = "/proc/kcore"
  condition:
    any of them
}
