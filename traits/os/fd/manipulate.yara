// Migrated from malcontent: os/fd/manipulate.yara

rule fcntl: harmless {
  meta:
    description = "manipulate file descriptor with fcntl"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "wpath"

  strings:
$ref = "fcntl" fullword
  condition:
    any of them
}
