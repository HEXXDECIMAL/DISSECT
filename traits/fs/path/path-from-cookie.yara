// Migrated from malcontent: fs/path/path-from-cookie.yara

rule lookup_dcookie {
  meta:
    description = "return a directory entry's path by cookie"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "lookup_dcookie"

  strings:
$ref = "lookup_dcookie" fullword
  condition:
    any of them
}
