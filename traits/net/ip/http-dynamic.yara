// Migrated from malcontent: c2/addr/http-dynamic.yara

rule http_dynamic: medium {
  meta:
    description = "URL that is dynamically generated"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$ref  = /https*:\/\/%s[\/\w\.]{0,64}/
    $ref2 = "https://%@:%@%@"
  condition:
    any of them
}
