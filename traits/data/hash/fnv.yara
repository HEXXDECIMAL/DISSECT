// Migrated from malcontent: data/hash/fnv.yara

rule crypto_fnv {
  meta:
    description = "Uses FNV hash algorithm"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "hash/fnv"
  condition:
    any of them
}
