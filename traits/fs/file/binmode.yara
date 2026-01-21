// Migrated from malcontent: fs/file/binmode.yara

rule ruby_binmode: medium {
  meta:
    description = "writes to files in binary mode"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = /\.binmode/ fullword
  condition:
    any of them
}
