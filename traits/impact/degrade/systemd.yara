// Migrated from malcontent: impact/degrade/systemd.yara

rule systemd_disabler: medium {
  meta:
    description = "disables systemd services"
    mbc         = "OB0010"
    attack      = "T1499"
    confidence  = "0.66"

  strings:
$ref = "systemctl disable"
  condition:
    filesize < 10MB and any of them
}

rule systemd_disabler_high: high {
  meta:
    description = "disables arbitrary systemd services, hiding output"
    confidence  = "0.66"

  strings:
$ref = "systemctl disable %s 2>/dev/null"
  condition:
    filesize < 10MB and any of them
}
