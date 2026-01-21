// Migrated from malcontent: os/env/unset.yara

rule unsetenv: harmless {
  meta:
    confidence  = "0.66"

  strings:
$ref = "unsetenv" fullword
  condition:
    any of them
}
