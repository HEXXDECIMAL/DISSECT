// Migrated from malcontent: credential/keylogger.yara

rule keylogger: medium {
  meta:
    description = "references a 'keylogger'"
    confidence  = "0.66"

  strings:
$ref = /[\w\_]{0,64}[kK]eylogger[\w\_]{0,64}/ fullword
  condition:
    any of them
}

rule start_keylogger: high {
  meta:
    description = "references starting a 'keylogger'"
    confidence  = "0.66"

  strings:
$ref = /start[\w\_]{0,8}[kK]eylogger[\w\_]{0,64}/ fullword
  condition:
    any of them
}
