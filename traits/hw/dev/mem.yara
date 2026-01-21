// Migrated from malcontent: hw/dev/mem.yara

rule dev_mem: medium linux {
  meta:
    description = "access raw system memory"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val        = "/dev/mem"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    $not_no     = "no /dev/mem" fullword
  condition:
    filesize < 10MB and uint32(0) == 1179403647 and $val and none of ($not*)
}

rule comsvcs_minidump: high windows {
  meta:
    description = "dump process memory using comsvcs.ddl"
    confidence  = "0.66"
    author      = "Florian Roth"

  strings:
$ref = /comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/
  condition:
    any of them
}

rule memdump: medium {
  meta:
    description = "dumps system memory"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$ = "memdump" fullword
    $ = "dumpmem" fullword
  condition:
    filesize < 10MB and any of them
}
