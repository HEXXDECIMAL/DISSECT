// Migrated from malcontent: net/tcp/synflood.yara

rule synflood: medium {
  meta:
    description = "References SYN flooding"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "synflood" fullword
    $ref2 = "attack_SYN" fullword
  condition:
    any of them
}
