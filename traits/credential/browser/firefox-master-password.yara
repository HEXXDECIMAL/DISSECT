// Migrated from malcontent: credential/browser/firefox-master_password.yara

rule firefox_master_password: high {
  meta:
    description = "Decrypts Firefox master password"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"

  strings:
$firefox    = "Firefox"
    $nssPrivate = "nssPrivate"
  condition:
    all of them
}
