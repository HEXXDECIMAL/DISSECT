// Migrated from malcontent: mem/anonymous-file.yara

rule memfd_create: medium {
  meta:
    description = "create an anonymous file"
    confidence  = "0.66"
    syscall     = "memfd_create"
    capability  = "CAP_IPC_LOCK"

  strings:
$ref = "memfd_create" fullword
    $go  = "MemfdCreate"
  condition:
    any of them
}

rule go_memfd_create: high {
  meta:
    description = "create an anonymous file"
    confidence  = "0.66"
    syscall     = "memfd_create"
    capability  = "CAP_IPC_LOCK"
    filetypes   = "elf,go,macho"

  strings:
$go = "MemfdCreate"
  condition:
    any of them
}
