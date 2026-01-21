// Migrated from malcontent: fs/swap/swap-off.yara

rule swapoff {
  meta:
    description = "stop swapping to a file/device"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "swapoff"

  strings:
$ref = "swapoff" fullword
  condition:
    any of them
}
