// Migrated from malcontent: hw/urandom.yara

rule urandom: harmless {
  meta:
    description = "references /dev/urandom"
    capability  = "true"
    confidence  = "0.66"

  strings:
$urandom = "/dev/urandom" fullword
  condition:
    any of them
}
