// Migrated from malcontent: anti-static/obfuscation/syscall.yara

rule syscall: medium {
  meta:
    description = "directly invokes syscalls"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"
    filetypes   = "rb"

  strings:
$ruby    = "ruby" fullword
    $require = "require" fullword
    $syscall = /syscall \d{1,3}/
  condition:
    filesize < 64KB and any of ($r*) and $syscall
}

rule go_raw_syscall: medium {
  meta:
    description = "invokes raw system calls"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$go = "unix.RawSyscall"
  condition:
    any of them
}
