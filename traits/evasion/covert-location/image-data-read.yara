// Migrated from malcontent: evasion/covert-location/image-data-read.yara

rule eval_image_data {
  meta:
    description = "Extracts content from an inline image/png"
    confidence  = "0.66"

  strings:
$eval = "<img src=\"data:image/png;(.*)\""
  condition:
    any of them
}
