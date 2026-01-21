// Migrated from malcontent: data/embedded/embedded-base64-zip.yara

rule base64_zip: high {
  meta:
    description = "Contains base64 zip file content"
    capability  = "true"
    confidence  = "0.66"

  strings:
$header = "UEsDBB"
  condition:
    $header
}
