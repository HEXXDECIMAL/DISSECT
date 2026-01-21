// Migrated from malcontent: fs/tempfile.yara

rule mktemp {
  meta:
    description = "creates temporary files"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref  = "mktemp" fullword
    $ref2 = "temp file"
    $ref3 = "ioutil/tempfile"
    $ref4 = "tmpfile"
    $ref5 = "createTempFile"
  condition:
    any of them
}
