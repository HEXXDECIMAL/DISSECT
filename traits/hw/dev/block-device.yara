// Migrated from malcontent: hw/dev/block-device.yara

rule block_devices: medium linux {
  meta:
    description = "works with block devices"
    confidence  = "0.66"

  strings:
$sys_val     = /\/sys\/block[\$%\w\{\}]{0,16}/
    $sys_dev_val = /\/sys\/dev\/block[\$%\w\{\}]{0,16}/
    $dev_block   = /\/dev\/block\/[\$%\w\{\}]{0,16}/
  condition:
    any of them
}

rule dev_sd: medium linux {
  meta:
    description = "access raw generic block devices"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = /\/dev\/sd[\$%\w\{\}]{0,10}/
  condition:
    any of them
}
