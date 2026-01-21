// Migrated from malcontent: net/ip/ip-parse.yara

rule inet_addr: medium {
  meta:
    description = "parses IP address"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref = "inet_addr"
  condition:
    any of them
}

rule inet_pton: medium {
  meta:
    description = "parses IP address (IPv4 or IPv6)"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref = "inet_pton"
  condition:
    any of them
}

rule ip_go: medium {
  meta:
    description = "parses IP address (IPv4 or IPv6)"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref  = "IsSingleIP"
    $ref2 = "IsLinkLocalUnicast"
  condition:
    any of them
}
