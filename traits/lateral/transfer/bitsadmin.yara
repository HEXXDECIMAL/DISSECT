// Migrated from malcontent: c2/tool_transfer/bitsadmin.yara

rule bitsadmin: medium {
  meta:
    description = "mentions 'bitsadmin', often used for file transfers"
    mbc         = "OB0013"
    attack      = "T1021"
    confidence  = "0.66"

  strings:
$bitsadmin = "bitsadmin" fullword
  condition:
    filesize < 250KB and all of them
}

rule bitsadmin_transfer: high {
  meta:
    description = "transfers files via 'bitsadmin'"
    confidence  = "0.66"

  strings:
$bitsadmin = "bitsadmin"
    $transfer  = "transfer"
    $wscript   = "wscript"
  condition:
    filesize < 250KB and all of them
}
