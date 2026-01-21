// Migrated from malcontent: data/encoding/utf16.yara

rule chr: medium {
  meta:
    description = "assembles strings from UTF-16 code units"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /.{0,8}fromCharCode.{0,8}/
  condition:
    any of them
}
