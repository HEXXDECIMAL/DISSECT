// Migrated from malcontent: fs/file/file-truncate.yara

rule ftruncate {
  meta:
    description = "truncate a file to a specified length"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "ftruncate"

  strings:
$ref  = "ftruncate64" fullword
    $ref2 = "ftruncate" fullword
  condition:
    any of them
}

rule truncate: harmless {
  meta:
    description = "truncate a file to a specified length"
    confidence  = "0.66"
    syscall     = "truncate"

  strings:
$ref = "truncate" fullword
  condition:
    any of them
}
