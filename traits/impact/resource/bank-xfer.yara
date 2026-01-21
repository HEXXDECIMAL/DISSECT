// Migrated from malcontent: impact/resource/bank_xfer.yara

rule bank_xfer: medium {
  meta:
    description = "references 'bank transfer'"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$bank_transfer = "bank transfer"
  condition:
    any of them
}
