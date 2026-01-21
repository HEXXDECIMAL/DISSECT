// Migrated from malcontent: data/random/bytes.yara

rule generate_rand {
  meta:
    description = "generates random bytes"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = ".randomBytes(" fullword
  condition:
    any of them
}
