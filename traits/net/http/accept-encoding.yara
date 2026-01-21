// Migrated from malcontent: net/http/accept-encoding.yara

rule content_type {
  meta:
    description = "set HTTP response encoding format (example: gzip)"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"
    ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding"

  strings:
$ref = "Accept-Encoding"
  condition:
    any of them
}
