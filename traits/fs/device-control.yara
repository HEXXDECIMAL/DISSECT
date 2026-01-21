// Migrated from malcontent: fs/device-control.yara

rule ioctl: harmless {
  meta:
    description = "manipulate the device parameters of special files"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "wpath"
    syscall     = "ioctl"

  strings:
$ioctl = "ioctl" fullword
  condition:
    any of them
}
