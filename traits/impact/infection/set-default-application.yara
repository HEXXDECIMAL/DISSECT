// Migrated from malcontent: impact/infection/set-default-application.yara

rule macos_setApp {
  meta:
    confidence  = "0.66"

  strings:
$setApp = "setApp:for"
    $sda    = "setting default application"
  condition:
    any of them
}
