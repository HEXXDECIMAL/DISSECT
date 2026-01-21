// Migrated from malcontent: privesc/setuid.yara

rule setuid {
  meta:
    description = "set real and effective user ID of current process"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"
    syscall     = "setuid"
    pledge      = "id"
    capability  = "CAP_SETUID"
    ref         = "https://man7.org/linux/man-pages/man2/setuid.2.html"

  strings:
$ref    = "setuid" fullword
    $not_go = "_syscall.libc_setuid_trampoline"
    $not_ls = "file that is setuid"
  condition:
    $ref and none of ($not*)
}

rule seteuid {
  meta:
    description = "set effective user ID of current process"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"
    syscall     = "seteuid"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/seteuid.2.html"
    capability  = "CAP_SETUID"

  strings:
$ref = "seteuid" fullword
  condition:
    any of them
}

rule setreuid {
  meta:
    description = "set real and effective user ID of current process"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"
    syscall     = "setreuid"
    pledge      = "id"
    capability  = "CAP_SETUID"
    ref         = "https://man7.org/linux/man-pages/man2/setreuid.2.html"

  strings:
$ref = "setreuid" fullword
  condition:
    any of them
}

rule setresuid {
  meta:
    description = "set real, effective, and saved user ID of process"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"
    syscall     = "setresuid"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/setresuid.2.html"
    capability  = "CAP_SETUID"

  strings:
$ref = "setresuid" fullword
  condition:
    any of them
}

rule setfsuid {
  meta:
    description = "set user identity used for filesystem checks"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"
    syscall     = "setfsuid"
    pledge      = "id"
    ref         = "https://man7.org/linux/man-pages/man2/setfsuid.2.html"
    capability  = "CAP_SETUID"

  strings:
$ref = "setfsuid" fullword
  condition:
    any of them
}

rule ruby_setuid_0: high {
  meta:
    description = "sets uid to 0 (root)"
    mbc         = "E1548"
    attack      = "T1548.001"
    confidence  = "0.66"

  strings:
$ref = "setuid(0)" fullword
  condition:
    any of them
}
