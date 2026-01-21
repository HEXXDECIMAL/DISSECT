// Migrated from malcontent: evasion/logging/current_logins.yara

rule current_logins: medium {
  meta:
    description = "accesses current logins"
    confidence  = "0.66"

  strings:
$f_wtmp     = "/var/log/wtmp"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
  condition:
    any of ($f*) and none of ($not*)
}
