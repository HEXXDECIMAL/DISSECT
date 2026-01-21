// Migrated from malcontent: net/http/http2.yara

rule http2 {
  meta:
    description = "Uses the HTTP/2 protocol"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref = "HTTP/2" fullword
  condition:
    any of them
}
