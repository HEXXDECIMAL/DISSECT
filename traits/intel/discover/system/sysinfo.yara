// Migrated from malcontent: discover/system/sysinfo.yara

rule sysinfo: medium {
  meta:
    description = "get system information (load, swap)"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    syscall     = "sysinfo"
    ref         = "https://man7.org/linux/man-pages/man2/sysinfo.2.html"

  strings:
$sysinfo    = "sysinfo" fullword
    $systeminfo = "systeminfo"
  condition:
    any of them
}
