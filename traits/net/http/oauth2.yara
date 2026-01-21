// Migrated from malcontent: net/http/oauth2.yara

rule oauth2 {
  meta:
    description = "supports OAuth2"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref  = "oauth2" fullword
    $ref2 = "OAuth 2"
  condition:
    any of them
}

rule token {
  meta:
    description = "supports OAuth2"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref  = "clientId"
    $ref2 = "refreshTok"
    $ref3 = "clientSecr"
  condition:
    all of them
}
