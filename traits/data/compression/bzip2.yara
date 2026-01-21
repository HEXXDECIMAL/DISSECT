// Migrated from malcontent: data/compression/bzip2.yara

rule bzip2 {
  meta:
    description = "Works with bzip2 files"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "bzip2" fullword
  condition:
    any of them
}
