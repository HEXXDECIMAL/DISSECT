// Migrated from malcontent: net/socket/socket-options-set.yara

rule setsockopt: harmless {
  meta:
    description = "set socket options"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "setsockopt"

  strings:
$setsockopt = "setsockopt" fullword
    $Setsockopt = "Setsockopt" fullword
  condition:
    any of them
}

rule go_setsockopt_int: medium {
  meta:
    description = "set socket options by integer"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "setsockopt"
    filetypes   = "elf,go,macho"

  strings:
$setsockopt = "SetsockoptInt"
  condition:
    any of them
}
