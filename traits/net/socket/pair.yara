// Migrated from malcontent: net/socket/pair.yara

rule socket_pair: medium {
  meta:
    description = "create a pair of connected sockets"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$socket = "socketpair" fullword
  condition:
    any of them
}
