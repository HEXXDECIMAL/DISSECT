// Migrated from malcontent: fs/inode-flags.yara

rule ioctl_iflags {
  meta:
    description = "ioctl operations for inode flags"
    confidence  = "0.66"
    pledge      = "wpath"
    syscall     = "ioctl_iflags"
    capability  = "CAP_FOWNER"

  strings:
$ioctl = "ioctl_iflags" fullword
  condition:
    any of them
}
