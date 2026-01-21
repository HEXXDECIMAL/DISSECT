// Migrated from malcontent: net/socket/socket_filter.yara

rule linux_network_filter: medium {
  meta:
    description = "listens for packets without a socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$0x     = "=0x"
    $p_tcp  = "tcp["
    $p_udp  = "udp["
    $p_icmp = "icmp["
  condition:
    $0x and any of ($p*)
}
