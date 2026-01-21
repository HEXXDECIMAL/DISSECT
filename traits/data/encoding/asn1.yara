// Migrated from malcontent: data/encoding/asn1.yara

rule go_asn1: harmless {
  meta:
    confidence  = "0.66"

  strings:
$gocsv     = "encoding/asn1"
    $unmarshal = "asn1.parse"
  condition:
    any of them
}
