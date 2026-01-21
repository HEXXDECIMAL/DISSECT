// Migrated from malcontent: persist/windows_start.yara

rule autorun: high {
  meta:
    description = "Accesses Windows Start Menu"
    confidence  = "0.66"

  strings:
$ref  = "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    $ref2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
  condition:
    any of them
}
