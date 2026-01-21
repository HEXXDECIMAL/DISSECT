// Migrated from malcontent: credential/server/htpasswd.yara

rule htpasswd: medium {
  meta:
    description = "Access .htpasswd files"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"

  strings:
$ref  = ".htpasswd"
    $ref2 = "Htpasswd"
  condition:
    any of them
}
