// Migrated from malcontent: credential/ssl/ssl-private.yara

rule etc_ssl_private: medium {
  meta:
    description = "access SSL private key material"
    mbc         = "OB0004"
    attack      = "T1552.004"
    confidence  = "0.66"

  strings:
$ref = "/etc/ssl/private"
  condition:
    any of them
}
