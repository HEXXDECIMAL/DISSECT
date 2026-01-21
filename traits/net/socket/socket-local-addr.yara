// Migrated from malcontent: net/socket/socket-local_addr.yara

rule getsockname: posix low {
  meta:
    description = "get local address of connected socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "getsockname"
    ref         = "https://man7.org/linux/man-pages/man2/getsockname.2.html"

  strings:
$ref = "getsockname" fullword
  condition:
    any of them
}
