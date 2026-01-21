// Migrated from malcontent: net/tcp/attack.yara

rule tcp_attack: medium {
  meta:
    description = "References TCP attack"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "tcp_attack" fullword
    $ref2 = "attack_tcp" fullword
  condition:
    any of them
}
