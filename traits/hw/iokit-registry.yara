// Migrated from malcontent: hw/iokit-registry.yara

rule IORegistry {
  meta:
    description = "access IOKit device driver registry"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "IORegistry"
  condition:
    any of them
}
