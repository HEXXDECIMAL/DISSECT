// Migrated from malcontent: net/dns/dns-txt.yara

rule dns_txt {
  meta:
    description = "Uses DNS TXT (text) records"
    mbc         = "C0003"
    attack      = "T1071.004"
    confidence  = "0.66"

  strings:
$dns = "dns"
    $txt = "TXT"
  condition:
    all of them
}
