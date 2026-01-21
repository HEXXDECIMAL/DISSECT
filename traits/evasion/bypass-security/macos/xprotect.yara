// Migrated from malcontent: evasion/bypass_security/macos/xprotect.yara

rule XProtectMention: medium {
  meta:
    description = "mentions 'XProtect'"
    confidence  = "0.66"

  strings:
$xprotect    = "XProtect"
    $not_apple   = "com.apple.private"
    $not_osquery = "OSQUERY_WORKER"
    $not_kandji  = "com.kandji.profile.mdmprofile"
  condition:
    $xprotect and none of ($not*)
}
