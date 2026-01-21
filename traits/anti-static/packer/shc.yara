// Migrated from malcontent: anti-static/packer/shc.yara

rule shc: high {
  meta:
    description = "Binary generated with SHC (Shell Script Compiler)"
    confidence  = "0.66"
    ref         = "https://github.com/neurobin/shc"

  strings:
$ref = "argv[0] nor $_"
  condition:
    $ref
}
