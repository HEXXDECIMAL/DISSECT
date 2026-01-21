// Migrated from malcontent: net/dns/dns-over-https.yara

rule doh_refs: medium {
  meta:
    description = "Supports DNS (Domain Name Service) over HTTPS"
    mbc         = "C0003"
    attack      = "T1071.004"
    confidence  = "0.66"

  strings:
$doh_Provider = "doh.Provider"
    $DnsOverHttps = "DnsOverHttps"
    $contentType  = "application/dns-message"
    $dnspod       = "dnspod"
    $doh_url      = "doh-url" fullword
    $cloudflare   = "https://9.9.9.9/dns-query"
  condition:
    any of them
}
