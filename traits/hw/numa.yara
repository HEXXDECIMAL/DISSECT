// Migrated from malcontent: hw/numa.yara

rule move_pages: harmless {
  meta:
    description = "move pages of a process to another node"
    confidence  = "0.66"
    capability  = "CAP_SYS_NICE"
    syscall     = "move_pages"

  strings:
$ref = "move_pages" fullword
  condition:
    any of them
}

rule migrate_pages: harmless {
  meta:
    description = "migrate pages of a process to another node"
    confidence  = "0.66"
    capability  = "CAP_SYS_NICE"
    syscall     = "migrate_pages"

  strings:
$ref = "migrate_pages" fullword
  condition:
    any of them
}
