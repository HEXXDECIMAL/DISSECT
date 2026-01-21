// Migrated from malcontent: fs/tempdir/TEMP.yara

rule temp {
  meta:
    confidence  = "0.66"

  strings:
$ref     = "temp" fullword
    $ref2    = "TEMP" fullword
    $env_get = "os.environ"
    $env_os  = "getenv"
  condition:
    any of ($env*) and any of ($ref*)
}
