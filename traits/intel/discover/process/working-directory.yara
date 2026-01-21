// Migrated from malcontent: discover/process/working_directory.yara

rule getcwd: harmless {
  meta:
    description = "gets current working directory"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    pledge      = "rpath"
    syscall     = "getcwd"

  strings:
$getcwd = "getcwd" fullword
  condition:
    any of them
}

rule getwd: harmless {
  meta:
    description = "gets current working directory"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    pledge      = "rpath"
    syscall     = "getwd"

  strings:
$getwd    = "getwd" fullword
    $go_Getwd = "Getwd" fullword
  condition:
    any of them
}

rule pwd: low {
  meta:
    description = "gets current working directory"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"

  strings:
$pwd = /["']pwd['"]/ fullword
  condition:
    any of them
}
