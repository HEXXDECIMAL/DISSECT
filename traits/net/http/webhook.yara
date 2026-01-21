// Migrated from malcontent: net/http/webhook.yara

rule webhook: medium {
  meta:
    description = "supports webhooks"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref = /[a-zA-Z]{0,16}[wW]eb[hH]ook[\w]{0,32}/ fullword
  condition:
    any of them
}
