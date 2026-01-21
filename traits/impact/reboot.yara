// Migrated from malcontent: impact/reboot.yara

rule _reboot: harmless {
  meta:
    description = "reboot system"
    confidence  = "0.66"
    capability  = "CAP_SYS_BOOT"

  strings:
$ref        = "_reboot" fullword
    $not_master = "master_reboot"
  condition:
    $ref and none of ($not*)
}

rule kexec_load {
  meta:
    description = "load a new kernel for later execution"
    confidence  = "0.66"
    capability  = "CAP_SYS_BOOT"

  strings:
$ref  = "kexec_load" fullword
    $ref2 = "kexec_file_load" fullword
  condition:
    any of them
}

rule reboot_command: medium {
  meta:
    description = "Forcibly reboots machine"
    confidence  = "0.66"

  strings:
$usr_sbin = "/usr/sbin/reboot" fullword
    $sbin     = "/sbin/reboot" fullword
    $bin      = "/bin/reboot" fullword
    $usr_bin  = "/usr/bin/reboot" fullword
  condition:
    any of them
}
