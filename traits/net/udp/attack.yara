// Migrated from malcontent: net/udp/attack.yara

rule udp_attack: high {
  meta:
    description = "References UDP attack"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "udp_attack" fullword
    $ref2 = "attack_udp" fullword
  condition:
    any of them
}
