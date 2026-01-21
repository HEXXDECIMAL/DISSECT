// Migrated from malcontent: evasion/indicator_blocking/vm.yara

rule hidden_qemu: medium {
  meta:
    description = "operates a QEMU VM"
    confidence  = "0.66"

  strings:
$s_qemu_exec = "qemu/exec.c"
    $s_model     = "unable to find CPU model '%s'"
    $s_qemu_vfio = "QEMU_VFIO"
  condition:
    1 of them
}

rule custom_qemu: high {
  meta:
    description = "custom build of QEMU"
    confidence  = "0.66"

  strings:
$custom = /\/Users\/[\w\/\.]{1,64}\/qemu\/exec.c/
  condition:
    1 of them
}
