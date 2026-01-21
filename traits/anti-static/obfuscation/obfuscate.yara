// Migrated from malcontent: anti-static/obfuscation/obfuscate.yara

rule obfuscate {
  meta:
    description = "Mentions the word obfuscate"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$obfuscate  = /obfuscate[\w]{0,32}/
    $not_ticket = "obfuscatedTicket"
  condition:
    $obfuscate and none of ($not*)
}

rule obfuscator {
  meta:
    description = "Mentions the word obfuscator"
    mbc         = "E1027"
    attack      = "T1027"
    confidence  = "0.66"

  strings:
$obfuscate = /[\w]{0,8}obfuscator/
  condition:
    $obfuscate
}
