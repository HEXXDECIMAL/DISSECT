// Migrated from malcontent: exfil/collection.yara

rule collect_data: medium {
  meta:
    description = "Uses terms that reference data collection"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$ref  = "collect_data"
    $ref2 = "CollectData"
    $ref3 = "DataCollection"
  condition:
    any of them
}
