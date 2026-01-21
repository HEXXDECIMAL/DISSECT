// Migrated from malcontent: fs/tempdir/TMPDIR.yara

rule TMPDIR {
  meta:
    confidence  = "0.66"

  strings:
$ref    = "TMPDIR" fullword
    $getenv = "getenv"
  condition:
    all of them
}
