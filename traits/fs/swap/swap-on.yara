// Migrated from malcontent: fs/swap/swap-on.yara

rule swapon {
  meta:
    description = "start swapping to a file/device"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "swapon"

  strings:
$ref = "swapon" fullword
  condition:
    any of them
}
