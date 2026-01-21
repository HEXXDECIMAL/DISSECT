// Migrated from malcontent: data/compression/xz.yara

rule xz_command: medium {
  meta:
    description = "command shells out to xz"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "xz -"
  condition:
    $ref
}

rule xz_lib: medium {
  meta:
    description = "uses xz library"
    confidence  = "0.66"

  strings:
$ref = "ulikunitz/xz"
  condition:
    $ref
}
