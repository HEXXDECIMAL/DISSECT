// Migrated from malcontent: net/ip/ip.yara

rule packets {
  meta:
    description = "access the internet"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$invalid_packet = "invalid packet" fullword
  condition:
    any of them
}
