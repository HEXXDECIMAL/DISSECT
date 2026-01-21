// Migrated from malcontent: data/encoding/url.yara

rule decode_uri_component: medium {
  meta:
    description = "decodes URL components"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "decodeURIComponent"
  condition:
    filesize < 1MB and $ref
}
