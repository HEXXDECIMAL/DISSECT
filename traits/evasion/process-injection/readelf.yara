// Migrated from malcontent: evasion/process_injection/readelf.yara

rule readelf: medium {
  meta:
    description = "analyzes or manipulates ELF files"
    confidence  = "0.66"

  strings:
$ref = "readelf" fullword
  condition:
    $ref
}
