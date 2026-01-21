// Migrated from malcontent: net/email/exotic_addr.yara

rule exotic_email_addr: medium {
  meta:
    description = "Contains an exotic email address"
    capability  = "true"
    confidence  = "0.66"

  strings:
$e_re = /[\w\.\-]{1,32}@(proton|tuta|mailfence|onion|gmx)[\w\.\-]{1,64}/
  condition:
    any of ($e*)
}
