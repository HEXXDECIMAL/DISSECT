// Migrated from malcontent: credential/password/hashcat.yara

rule hashcat: medium {
  meta:
    description = "References 'hashcat', a password cracking tool"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"

  strings:
$ref = "hashcat" fullword
  condition:
    $ref
}
