// Migrated from malcontent: privesc/uac_bypass.yara

rule uac_bypass: high windows {
  meta:
    description = "may bypass UAC (User Account Control)"
    mbc         = "E1548"
    attack      = "T1548.002"
    confidence  = "0.66"

  strings:
$uacbypass = "uacbypass" fullword
    $delegate  = "fodhelper" fullword
  condition:
    any of them
}
