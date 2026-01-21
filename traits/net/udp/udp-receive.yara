// Migrated from malcontent: net/udp/udp-receive.yara

rule udp_listen {
  meta:
    description = "Listens for UDP responses"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "listenUDP"
    $ref2 = "ReadFromUDP"
  condition:
    any of them
}
