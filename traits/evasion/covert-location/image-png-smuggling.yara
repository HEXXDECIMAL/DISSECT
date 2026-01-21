// Migrated from malcontent: evasion/covert-location/image-png-smuggling.yara

rule png: medium {
  meta:
    confidence  = "0.66"

  strings:
$eval = "<img src=\"data:image/png;(.*)\""
  condition:
    any of them
}
