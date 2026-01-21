// Migrated from malcontent: net/ip/ip-spoof.yara

rule ip_spoof: high {
  meta:
    description = "spoof IP addresses"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$ip_spoof = "ipspoof" fullword
  condition:
    any of them
}
