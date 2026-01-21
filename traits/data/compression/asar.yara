// Migrated from malcontent: data/compression/asar.yara

rule asar {
  meta:
    description = "works with ASAR (Electron Archive) files"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://www.electronjs.org/docs/latest/tutorial/asar-archives"

  strings:
$ref_extract = "asar.extractAll" fullword
    $ref_create  = "asar.createPackage" fullword
  condition:
    any of them
}
