// Migrated from malcontent: net/ip/ip-byte-order.yara

rule htonl: medium {
  meta:
    description = "convert values between host and network byte order"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref  = "htonl" fullword
    $ref2 = "htons" fullword
    $ref3 = "ntohs" fullword
  condition:
    any of them in (1300..3000)
}
