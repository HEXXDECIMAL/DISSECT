// Migrated from malcontent: net/http/http.yara

rule http: low {
  meta:
    description = "Uses the HTTP protocol"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref  = "http" fullword
    $ref2 = "HTTP"
  condition:
    any of them
}
