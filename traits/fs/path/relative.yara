// Migrated from malcontent: fs/path/relative.yara

rule relative_path_val: medium {
  meta:
    description = "references and possibly executes relative path"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref    = /\.\/[a-z_\-]{2,16}/ fullword
    $up_ref = /\.\.\/[a-z_\-]{2,16}/ fullword
  condition:
    $ref and not $up_ref
}
