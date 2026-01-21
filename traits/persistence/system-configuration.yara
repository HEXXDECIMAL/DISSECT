// Migrated from malcontent: persist/system-configuration.yara

rule systemsetup_no_sleep: medium {
  meta:
    description = "disables sleep mode"
    confidence  = "0.66"

  strings:
$no_sleep = "systemsetup -setcomputersleep Never"
  condition:
    filesize < 10485760 and any of them
}
