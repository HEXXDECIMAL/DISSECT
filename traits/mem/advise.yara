// Migrated from malcontent: mem/advise.yara

rule madvise: harmless {
  meta:
    description = "give advice about use of memory"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "madvise"

  strings:
$ref = "madvise" fullword
  condition:
    any of them
}
