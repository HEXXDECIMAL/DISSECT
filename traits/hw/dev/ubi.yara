// Migrated from malcontent: hw/dev/ubi.yara

rule ubi: high linux {
  meta:
    description = "access raw unsorted block images (UBI)"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = /\/dev\/ubi[\$%\w\{\}]{0,16}/
  condition:
    any of them
}

rule expected_ubi_users: override {
  meta:
    confidence  = "0.66"
    ubi         = "medium"

  strings:
$libuboot = "libuboot"
    $usage    = "Usage:"
    $ubi      = "ubifs" fullword
    $UBI      = "UBI version"
  condition:
    filesize < 512KB and ubi and any of them
}
