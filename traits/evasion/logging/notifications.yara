// Migrated from malcontent: evasion/logging/notifications.yara

rule killall_NotificationCenter: high macos {
  meta:
    description = "kills the macOS NotificationCenter"
    confidence  = "0.66"

  strings:
$killall = "killall" fullword
    $nc      = "NotificationCenter" fullword
  condition:
    filesize < 1MB and all of them
}
