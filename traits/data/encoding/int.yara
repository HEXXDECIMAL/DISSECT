// Migrated from malcontent: data/encoding/int.yara

rule js_parseInt: low {
  meta:
    description = "parses integers"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "parseInt("
  condition:
    any of them
}

rule js_parseInt_Math: medium {
  meta:
    description = "performs math directly against parsed integers"
    confidence  = "0.66"

  strings:
$ref = /[\^\*\-\+]\s{0,2}parseInt\(/
  condition:
    any of them
}
