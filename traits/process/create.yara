// Migrated from malcontent: process/create.yara

rule _fork {
  meta:
    description = "create child process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"
    pledge      = "exec"
    syscall     = "fork"
    ref         = "https://man7.org/linux/man-pages/man2/fork.2.html"

  strings:
$fork = "_fork" fullword
  condition:
    any of them
}

rule fork {
  meta:
    description = "create child process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"
    pledge      = "exec"
    syscall     = "fork"
    ref         = "https://man7.org/linux/man-pages/man2/fork.2.html"

  strings:
$fork = "fork" fullword
  condition:
    any of them in (1000..3000)
}

rule syscall_vfork {
  meta:
    description = "create child process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"
    pledge      = "exec"
    syscall     = "vfork"
    ref         = "https://man7.org/linux/man-pages/man2/vfork.2.html"

  strings:
$vfork = "vfork" fullword
  condition:
    any of them
}

rule js_child_process: medium {
  meta:
    description = "create child process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"

  strings:
$child_process = /require\(['"]child_process['"]\)/
  condition:
    filesize < 1MB and any of them
}

rule syscall_clone: harmless {
  meta:
    description = "create child process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"
    pledge      = "exec"
    syscall     = "clone"
    ref         = "https://man7.org/linux/man-pages/man2/clone.2.html"

  strings:
$clone  = "clone" fullword
    $clone2 = "clone2" fullword
    $clone3 = "clone3" fullword
  condition:
    any of them
}

rule CreateProcess: low {
  meta:
    description = "create a new process"
    mbc         = "C0015"
    attack      = "T1106"
    confidence  = "0.66"

  strings:
$create = /CreateProcess\w{0,8}/
  condition:
    any of them
}
