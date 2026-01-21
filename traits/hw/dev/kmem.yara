// Migrated from malcontent: hw/dev/kmem.yara

rule kmem: high bsd {
  meta:
    description = "access raw kernel memory"
    confidence  = "0.66"
    capability  = "CAP_SYS_RAWIO"

  strings:
$val = "/dev/kmem"

    // entries from include/paths.h
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    $not_lsof   = "lsof" fullword
  condition:
    $val and none of ($not*)
}
