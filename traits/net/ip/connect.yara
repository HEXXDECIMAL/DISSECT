// Migrated from malcontent: net/ip/connect.yara

rule ip_connect: medium {
  meta:
    description = "opens a network connection"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$open_connection = "openConnection" fullword
  condition:
    any of them
}
