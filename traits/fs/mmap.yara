// Migrated from malcontent: fs/mmap.yara

rule mmap: harmless {
  meta:
    confidence  = "0.66"
    pledge      = "stdio"
    syscall     = "mmap"

  strings:
$ref = "_mmap" fullword
  condition:
    any of them
}
