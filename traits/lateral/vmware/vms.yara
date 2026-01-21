// Migrated from malcontent: lateral/vmware/vms.yara

rule vmware_vms: medium {
  meta:
    description = "gets a list of VMware VM IDs"
    mbc         = "OB0013"
    attack      = "T1021"
    confidence  = "0.66"

  strings:
$ref  = "vim-cmd"
    $ref2 = "vmsvc"
    $ref3 = "getallvm"
  condition:
    all of them
}
