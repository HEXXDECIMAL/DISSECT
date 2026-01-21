// Migrated from malcontent: data/encoding/protobuf.yara

rule protobuf: harmless {
  meta:
    confidence  = "0.66"

  strings:
$ref = "protobuf" fullword
  condition:
    any of them
}
