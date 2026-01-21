// Migrated from malcontent: hw/dev/sd_mmc.yara

rule dev_mmc: high {
  meta:
    description = "access raw SD/MMC devices"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$dev_mmc   = /\/dev\/mmcblk[\$%\w\{\}]{0,16}/
    $dev_block = /\/dev\/block\/mmcblk[\$%\w\{\}]{0,16}/
  condition:
    filesize < 10MB and any of ($dev*)
}

rule dev_mmc_ok: override {
  meta:
    confidence  = "0.66"
    dev_mmc     = "medium"

  strings:
$not_fwupd = "fu_firmware_set_id"
    $not_ipmi  = "/dev/ipmi"
    $not_grub  = "GRUB" fullword
  condition:
    dev_mmc and any of them
}
