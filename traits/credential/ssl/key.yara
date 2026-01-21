// Migrated from malcontent: credential/ssl/key.yara

rule from_secret_key: high {
  meta:
    description = "extracts data from a secret key"
    mbc         = "OB0004"
    attack      = "T1552.004"
    confidence  = "0.66"

  strings:
$key = "fromSecretKey"
  condition:
    $key
}
