// Migrated from malcontent: data/encoding/reverse.yara

rule strrev {
  meta:
    description = "reverses strings"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "strrev("
    $ref2 = /strrev\(['"].{0,256}['"]\);/
  condition:
    any of them
}
