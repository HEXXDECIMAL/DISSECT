// Migrated from malcontent: hw/dev/diskmapper.yara

rule dev_dm: medium linux {
  meta:
    description = "access raw LVM disk mapper devices"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = /\/dev\/dm-[\$%\w\{\}]{0,10}/
  condition:
    any of them
}
