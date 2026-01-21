// Migrated from malcontent: net/http/accept.yara

rule http_accept_json: low {
  meta:
    description = "accepts JSON files via HTTP"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref   = "Accept" fullword
    $mime  = "application/json"
    $mime2 = "application/ld+json"
  condition:
    $ref and any of ($mime*)
}

rule http_accept_binary: medium {
  meta:
    description = "accepts binary files via HTTP"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref   = "Accept" fullword
    $mime2 = "application/octet-stream"
  condition:
    $ref and any of ($mime*)
}
