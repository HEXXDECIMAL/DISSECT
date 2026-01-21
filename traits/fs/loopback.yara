// Migrated from malcontent: fs/loopback.yara

rule dev_loopback: medium linux {
  meta:
    description = "access virtual block devices (loopback)"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = /\/dev\/loop[\$%\w\{\}]{0,16}/
  condition:
    any of them
}
