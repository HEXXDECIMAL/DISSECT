// Migrated from malcontent: data/encoding/json.yara

rule encoding_json {
  meta:
    description = "Supports JSON encoded objects"
    capability  = "true"
    confidence  = "0.66"

  strings:
$jsone = "encoding/json"
  condition:
    any of them
}
