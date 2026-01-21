// Migrated from malcontent: lateral/scan/brute_force.yara

rule brute_force {
  meta:
    description = "May use bruteforce to function"
    mbc         = "OB0013"
    attack      = "T1046"
    confidence  = "0.66"

  strings:
$ref  = "brute force" fullword
    $ref1 = "bruteforce" fullword
    $ref2 = "brute-force" fullword
  condition:
    any of them
}
