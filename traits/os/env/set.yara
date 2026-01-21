// Migrated from malcontent: os/env/set.yara

rule setenv_putenv: harmless {
  meta:
    description = "places a variable into the environment"
    capability  = "true"
    confidence  = "0.66"

  strings:
$setenv = "setenv" fullword
    $putenv = "putenv" fullword
    $set    = /SetEnvironmentVariable\w{0,4}/
  condition:
    any of them
}
