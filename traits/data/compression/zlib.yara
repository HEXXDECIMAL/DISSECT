// Migrated from malcontent: data/compression/zlib.yara

rule zlib: low {
  meta:
    description = "uses zlib"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "zlib" fullword
  condition:
    $ref
}
