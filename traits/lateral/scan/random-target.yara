// Migrated from malcontent: lateral/scan/random_target.yara

rule random_target: medium {
  meta:
    description = "References a random target"
    mbc         = "OB0013"
    attack      = "T1046"
    confidence  = "0.66"

  strings:
$ref  = "random target"
    $ref2 = "RandomTarget"
    $ref3 = "randomIP"
    $ref4 = "getrandip" fullword
  condition:
    any of them
}
