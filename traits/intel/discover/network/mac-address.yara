// Migrated from malcontent: discover/network/mac-address.yara

rule macaddr: medium {
  meta:
    description = "Retrieves network MAC address"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ref  = "MAC address"
    $ref2 = "get_if_mac_addr"
    $ref3 = "macAddress" fullword
  condition:
    any of them
}

rule parse_macaddr: medium {
  meta:
    description = "Parses network MAC address"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$net_mac  = "net/mac.go" fullword
    $parsemac = "ParseMAC" fullword
  condition:
    any of them
}
