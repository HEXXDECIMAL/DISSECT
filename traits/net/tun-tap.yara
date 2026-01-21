// Migrated from malcontent: net/tun_tap.yara

rule tun_tap: medium linux {
  meta:
    description = "accesses the TUN/TAP device driver"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "/dev/net/tun" fullword
  condition:
    any of them
}
