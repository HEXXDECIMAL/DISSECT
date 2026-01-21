// Migrated from malcontent: fs/unmount.yara

rule umount {
  meta:
    description = "unmount file system"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "umount"

  strings:
$ref = "umount" fullword
  condition:
    any of them
}
