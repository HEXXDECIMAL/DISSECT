// Migrated from malcontent: impact/remote_access/implant.yara

rule implant: medium {
  meta:
    description = "References an Implant"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$ref            = "implant" fullword
    $ref2           = "IMPLANT" fullword
    $ref3           = "Implant"
    $not_ms_example = "Drive-by Compromise"
  condition:
    any of ($ref*) and none of ($not*)
}
