// Migrated from malcontent: discover/network/connectivity.yara

rule network_connectivity: low {
  meta:
    description = "checks Internet connectivity"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ref = "http://www.msftncsi.com/ncsi.txt"
  condition:
    any of them
}

rule bypass_gfw: medium {
  meta:
    description = "GFW bypass (Great Firewall of China)"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ref = "bypass GFW"
  condition:
    any of them
}
