// Migrated from malcontent: exfil/exfil.yara

rule exfil: medium {
  meta:
    description = "References 'exfil'"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$ref  = "exfil" fullword
    $ref2 = "exfiltrate" fullword
  condition:
    any of them
}
