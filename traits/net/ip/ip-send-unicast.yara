// Migrated from malcontent: net/ip/ip-send-unicast.yara

rule unicast {
  meta:
    description = "send data to the internet"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$unicast = "unicast" fullword
  condition:
    any of them
}
