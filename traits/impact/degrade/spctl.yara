// Migrated from malcontent: impact/degrade/spctl.yara

rule spctl_master_disable: critical {
  meta:
    description = "disables macOS Gatekeeper"
    mbc         = "OB0010"
    attack      = "T1499"
    confidence  = "0.66"

  strings:
$ref = "spctl --master-disable"
  condition:
    $ref
}
