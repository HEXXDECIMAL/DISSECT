// Migrated from malcontent: net/dns/dns.yara

rule go_dns_refs {
  meta:
    description = "Uses DNS (Domain Name Service)"
    mbc         = "C0003"
    attack      = "T1071.004"
    confidence  = "0.66"

  strings:
$dnsmessage = "dnsmessage"
    $edns       = "SetEDNS0"
    $cname      = "CNAMEResource"
    $nodejs     = /require\(['"]dns['"]\)/
  condition:
    any of them
}
