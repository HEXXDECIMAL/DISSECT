// Migrated from malcontent: data/hash/sha1.yara

rule SHA1 {
  meta:
    description = "Uses the SHA1 signature format"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "SHA1_"
  condition:
    any of them
}
