// Migrated from malcontent: evasion/logging/failed_logins.yara

rule failed_logins: medium {
  meta:
    description = "accesses failed logins"
    confidence  = "0.66"

  strings:
$f_wtmp     = "/var/log/btmp" fullword
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    $not_pam    = "Linux-PAM" fullword
  condition:
    any of ($f*) and none of ($not*)
}
