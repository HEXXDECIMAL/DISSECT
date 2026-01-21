// Migrated from malcontent: c2/tool_transfer/terminology.yara

rule payload_url: medium {
  meta:
    description = "References a 'payload URL'"
    mbc         = "OB0013"
    attack      = "T1021"
    confidence  = "0.66"

  strings:
$ref  = "payload_url" fullword
    $ref2 = "payload url" fullword
    $ref3 = "payload URL" fullword
  condition:
    any of them
}
