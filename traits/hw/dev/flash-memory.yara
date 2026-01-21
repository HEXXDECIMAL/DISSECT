// Migrated from malcontent: hw/dev/flash_memory.yara

rule dev_mtd: medium linux {
  meta:
    description = "access raw flash memory devices"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val       = /\/dev\/mtd[\$%\w\{\}]{0,16}/
    $block_val = /\/dev\/block\/mtdblock[\$%\w\{\}]{0,16}/
  condition:
    any of them
}
