// Migrated from malcontent: net/socket/socket-peer-address.yara

rule getpeername {
  meta:
    description = "get peer address of connected socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "getpeername"
    ref         = "https://man7.org/linux/man-pages/man2/getpeername.2.html"

  strings:
$ref         = "getpeername" fullword
    $client_addr = /client_addr[\w]{0,8}/
  condition:
    any of them
}
