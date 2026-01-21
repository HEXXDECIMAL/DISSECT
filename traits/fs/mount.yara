// Migrated from malcontent: fs/mount.yara

rule _mount {
  meta:
    description = "mounts file systems"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "mount"

  strings:
$ref = "_mount" fullword
  condition:
    any of them
}

rule mount {
  meta:
    description = "mounts file systems"
    confidence  = "0.66"
    capability  = "CAP_SYS_SYSADMIN"
    syscall     = "mount"

  strings:
$mount   = "mount" fullword
    $mounto  = "-o" fullword
    $fstab   = "fstab" fullword
    $remount = "remount" fullword
  condition:
    $mount and 2 of them
}
