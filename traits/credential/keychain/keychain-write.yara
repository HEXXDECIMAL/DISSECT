// Migrated from malcontent: credential/keychain/keychain-write.yara

rule keychain_write {
  meta:
    description = "Writes contents to the Keychain"
    mbc         = "OB0004"
    attack      = "T1555.001"
    confidence  = "0.66"

  strings:
$ref = "WriteDataToKeychain"
  condition:
    any of them
}
