// Migrated from malcontent: impact/infection/worm.yara

rule worm: medium {
  meta:
    description = "References 'Worm'"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$ref3 = "Worm" fullword
    $ref2 = /w{0,8}worm/ fullword
  condition:
    any of them
}
