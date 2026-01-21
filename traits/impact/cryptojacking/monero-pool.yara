// Migrated from malcontent: impact/cryptojacking/monero-pool.yara

rule monero_pool: medium {
  meta:
    description = "References Monero mining pools"
    mbc         = "OB0010"
    attack      = "T1496"
    confidence  = "0.66"

  strings:
$ref  = "monero"
    $ref2 = "pool"
  condition:
    all of them
}
