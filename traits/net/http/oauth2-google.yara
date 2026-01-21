// Migrated from malcontent: net/http/oauth2-google.yara

rule google_oauth2: medium {
  meta:
    description = "exchanges credentials with Google"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$o_google  = /googleapis.com\/oauth2\/[\w\/]{0,64}/
    $o_google1 = "accounts.google.com/o/oauth2/auth"
  condition:
    any of them
}
