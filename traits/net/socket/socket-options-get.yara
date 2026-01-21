// Migrated from malcontent: net/socket/socket-options-get.yara

rule getsockopt: harmless {
  meta:
    description = "get socket options"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "getsockopt"

  strings:
$setsockopt = "getsockopt" fullword
  condition:
    any of them
}
