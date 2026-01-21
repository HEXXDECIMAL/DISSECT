// Migrated from malcontent: os/kernel/key-management.yara

rule syscall_keyctl {
  meta:
    description = "kernel key management facility"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "keyctl"

  strings:
$ref = "keyctl"
  condition:
    any of them
}
