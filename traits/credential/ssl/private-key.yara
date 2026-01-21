// Migrated from malcontent: credential/ssl/private_key.yara

rule private_key_val {
  meta:
    description = "References private keys"
    mbc         = "OB0004"
    attack      = "T1552.004"
    confidence  = "0.66"

  strings:
$ref  = "private_key"
    $ref2 = "PRIVATE_KEY"
    $ref3 = "privateKey"
    $ref4 = "privatekey"
  condition:
    any of them
}
