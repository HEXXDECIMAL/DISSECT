// Migrated from malcontent: fs/path/boot.yara

rule boot_path: medium {
  meta:
    description = "path reference within /boot"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
  condition:
    $ref
}

rule elf_boot_path: medium {
  meta:
    description = "path reference within /boot"
    confidence  = "0.66"
    filetypes   = "elf"

  strings:
$ref              = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
    $not_kern         = "/boot/vmlinux-%s"
    $not_include_path = "_PATH_UNIX" fullword
  condition:
    uint32(0) == 1179403647 and $ref and none of ($not*)
}
