// Migrated from malcontent: data/compression/gzip.yara

rule gzip {
  meta:
    description = "works with gzip files"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://www.gnu.org/software/gzip/"

  strings:
$ref = "gzip" fullword
  condition:
    any of them
}
