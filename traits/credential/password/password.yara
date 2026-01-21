// Migrated from malcontent: credential/password/password.yara

rule password {
  meta:
    description = "references a 'password'"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"

  strings:
$ref  = /[a-zA-Z\-_ ]{0,16}password[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2 = /[a-zA-Z\-_ ]{0,16}Password[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}
