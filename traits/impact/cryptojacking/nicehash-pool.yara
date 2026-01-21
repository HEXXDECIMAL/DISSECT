// Migrated from malcontent: impact/cryptojacking/nicehash_pool.yara

rule nicehash_pool: high {
  meta:
    description = "References Nicehash and mining pools"
    mbc         = "OB0010"
    attack      = "T1496"
    confidence  = "0.66"

  strings:
$ref            = "nicehash" fullword
    $ref2           = "pool"
    $not_pypi_index = "testpack-id-lb001"
  condition:
    all of ($ref*) and none of ($not*)
}
