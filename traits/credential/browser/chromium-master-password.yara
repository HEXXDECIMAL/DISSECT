// Migrated from malcontent: credential/browser/chromium_master_password.yara

rule chromium_master_password: high {
  meta:
    description = "Decrypts Chromium master password"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"

  strings:
$local_state   = "Local State"
    $encrypted_key = "encrypted_key"
    $os_crypt      = "os_crypt"
  condition:
    all of them
}
