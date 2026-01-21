// Migrated from malcontent: anti-static/obfuscation/hidden_literals.yara

rule hidden_literals: medium {
  meta:
    description = "references hidden literals"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$ref = "hidden_literals"
  condition:
    filesize < 10MB and $ref
}
