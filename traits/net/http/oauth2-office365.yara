// Migrated from malcontent: net/http/oauth2-office365.yara

rule microsoft_oauth2: medium {
  meta:
    description = "exchanges credentials with Microsoft Office 365"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$o_microsoft1 = "login.microsoftonline.com/common/oauth2/v2.0/authorize"
  condition:
    any of them
}
