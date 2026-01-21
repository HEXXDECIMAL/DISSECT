// Migrated from malcontent: data/embedded/embedded-html.yara

rule html: medium {
  meta:
    description = "Contains HTML content"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "<html>"
    $ref2 = "<img src>"
    $ref3 = "<a href>"
    $ref4 = "DOCTYPE html"
    $ref5 = "<html lang"
  condition:
    any of them
}
