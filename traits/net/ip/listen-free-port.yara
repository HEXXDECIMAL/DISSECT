// Migrated from malcontent: net/ip/listen-free_port.yara

rule freeport: medium {
  meta:
    description = "find open TCP port to listen at"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$ref = "phayes/freeport"
  condition:
    any of them
}
