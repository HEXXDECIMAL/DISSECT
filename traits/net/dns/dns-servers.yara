// Migrated from malcontent: net/dns/dns-servers.yara

rule go_dns_refs_local {
  meta:
    description = "Examines local DNS servers"
    mbc         = "C0003"
    attack      = "T1071.004"
    confidence  = "0.66"

  strings:
$resolv         = "resolv.conf" fullword
    $dns_getservers = "dns.getServers"
    $cname          = "CNAMEResource"
  condition:
    any of them
}
