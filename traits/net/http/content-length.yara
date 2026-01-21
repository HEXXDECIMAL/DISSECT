// Migrated from malcontent: net/http/content-length.yara

rule content_length_0: medium {
  meta:
    description = "Sets HTTP content length to zero"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref = "Content-Length: 0"
  condition:
    $ref
}

rule content_length_hardcoded: high {
  meta:
    description = "Sets HTTP content length to hard-coded value"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref              = /Content-Length: \d{2,13}/ fullword
    $not_test_parse   = "test_parse"
    $not_slash_test   = "/test" fullword
    $not_test_message = "test_message"
    $not_unit_test    = "unit test"
  condition:
    $ref and none of ($not*)
}
