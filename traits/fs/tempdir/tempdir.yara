// Migrated from malcontent: fs/tempdir/tempdir.yara

rule tempdir {
  meta:
    description = "looks up location of temp directory"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "wpath"

  strings:
$gettempdir = "gettempdir" fullword
    $tempdir    = "TEMPDIR" fullword
    $tmpdir     = "TMPDIR" fullword
    $cocoa      = "NSTemporaryDirectory" fullword
    $powershell = "GetTempPath" fullword
  condition:
    any of them
}
