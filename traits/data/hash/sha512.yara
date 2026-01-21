// Migrated from malcontent: data/hash/sha512.yara

rule SHA512: harmless {
  meta:
    description = "Uses the SHA512 signature format"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "SHA512"
  condition:
    any of them
}
