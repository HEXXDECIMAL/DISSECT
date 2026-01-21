// Migrated from malcontent: hw/hardware-enumeration.yara

rule linux_dmidecode_hardware_profiler: medium linux {
  meta:
    description = "uses dmidecode to query for hardware information"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /dmidecode[ -\\w]{0,32}/
  condition:
    $ref
}
