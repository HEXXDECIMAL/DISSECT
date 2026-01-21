// Migrated from malcontent: net/socket/raw.yara

rule raw_sockets: medium {
  meta:
    description = "send raw and/or malformed IP packets"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAW"
    ref         = "https://man7.org/linux/man-pages/man7/raw.7.html"

  strings:
$ref          = "raw socket" fullword
    $hdrincl      = "HDRINCL" fullword
    $sock_raw     = "SOCK_RAW" fullword
    $ipproto_raw  = "IPPROTO_RAW" fullword
    $proc_net_raw = "/proc/net/raw"
    $make_ip      = "makeIPPacket"
    $impacket     = "impacket."
    $makePackets  = "makePacket" fullword
    $scapy        = /scapy.{0,32}Raw/ fullword
  condition:
    any of them
}
