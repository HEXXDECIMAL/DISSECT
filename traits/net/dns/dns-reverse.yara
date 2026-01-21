// Migrated from malcontent: net/dns/dns-reverse.yara

rule in_addr_arpa: medium {
  meta:
    description = "looks up the reverse hostname for an IP"
    mbc         = "C0003"
    attack      = "T1071.004"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ref  = ".in-addr.arpa"
    $ref2 = "ip6.arpa"
  condition:
    any of them
}
