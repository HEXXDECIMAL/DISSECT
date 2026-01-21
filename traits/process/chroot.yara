// Migrated from malcontent: process/chroot.yara

rule chroot {
  meta:
    description = "change the location of root for the process"
    confidence  = "0.66"
    capability  = "CAP_SYS_CHROOT"
    syscall     = "chroot"

  strings:
$ref = "chroot" fullword
  condition:
    any of them
}
