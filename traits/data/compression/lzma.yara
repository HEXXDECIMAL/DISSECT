// Migrated from malcontent: data/compression/lzma.yara

rule lzma {
  meta:
    description = "works with lzma files"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm"

  strings:
$ref = "lzma" fullword
  condition:
    any of them
}
