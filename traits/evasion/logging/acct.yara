// Migrated from malcontent: evasion/logging/acct.yara

rule acct {
  meta:
    description = "switch process accounting on or off"
    confidence  = "0.66"
    capability  = "CAP_SYS_ACCT"

  strings:
$ref = "acct" fullword

    // from /etc/services
    $not_radius = "radius-acct" fullword
  condition:
    any of them
}
