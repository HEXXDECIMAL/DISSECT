// Migrated from malcontent: os/kernel/netlink.yara

rule netlink {
  meta:
    description = "communicate with kernel services"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "nl_socket" fullword
    $ref2 = "AF_NETLINK" fullword
    $ref3 = "nl_connect" fullword
    $ref4 = "netlink" fullword
  condition:
    any of them
}
