// Migrated from malcontent: impact/ui/alert.yara

rule notification_dialog_with_sysctl_and_curl {
  meta:
    description = "Shows an alert dialog"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$ref = "CFUserNotificationDisplayAlert"
  condition:
    $ref
}
