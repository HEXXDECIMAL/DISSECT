// Migrated from malcontent: impact/shutdown.yara

rule shutdown_val: medium {
  meta:
    description = "calls shutdown command"
    confidence  = "0.66"

  strings:
$ref  = /shutdown -[\w ]{0,16}/
    $ref2 = "shutdown now"
  condition:
    any of them
}

rule shutdown_windows: high windows {
  meta:
    description = "shuts machine down"
    confidence  = "0.66"

  strings:
$powerstate = "SetSystemPowerState(0,"
  condition:
    any of them
}
