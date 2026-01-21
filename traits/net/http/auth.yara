// Migrated from malcontent: net/http/auth.yara

rule http_auth {
  meta:
    description = "makes HTTP requests with basic authentication"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref  = "Www-Authenticate"
    $ref2 = "WWW-Authenticate"
    $ref3 = "www-authenticate"
  condition:
    any of them
}

rule bearer_auth {
  meta:
    description = "makes HTTP requests with Bearer authentication"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref  = "Authorization" fullword
    $ref2 = "Bearer" fullword
    $ref3 = /[A-Z_]{0,16}TOKEN/
  condition:
    all of them or ($ref and $ref2)
}
