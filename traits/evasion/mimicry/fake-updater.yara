// Migrated from malcontent: evasion/mimicry/fake-updater.yara

rule fake_chrome_update: high {
  meta:
    description = "May fake being a Chrome update"
    confidence  = "0.66"

  strings:
$ref     = "GoogleChromeUpdate"
    $updater = "com.google.Chrome.UpdaterPrivilegedHelper"
  condition:
    $ref and not $updater
}
