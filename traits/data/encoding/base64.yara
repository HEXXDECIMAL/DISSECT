// Migrated from malcontent: data/encoding/base64.yara

rule b64 {
  meta:
    description = "Supports base64 encoded strings"
    capability  = "true"
    confidence  = "0.66"

  strings:
$base64   = "base64"
    $certutil = "certutil -decode"
  condition:
    any of them
}
