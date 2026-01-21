// Migrated from malcontent: discover/system/machine_id.yara

rule machineid {
  meta:
    description = "Gets a unique machineid for the host"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$ref = "machineid"
  condition:
    any of them
}
