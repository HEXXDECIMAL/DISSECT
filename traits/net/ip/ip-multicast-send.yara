// Migrated from malcontent: net/ip/ip-multicast-send.yara

rule multicast {
  meta:
    description = "send data to multiple nodes simultaneously"
    mbc         = "C0001"
    confidence  = "0.66"
    ref         = "https://en.wikipedia.org/wiki/IP_multicast"

  strings:
$multicast = "multicast" fullword
  condition:
    any of them
}
