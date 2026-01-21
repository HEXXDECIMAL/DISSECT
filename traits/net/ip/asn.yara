// Migrated from malcontent: net/ip/asn.yara

rule asn {
  meta:
    description = "Uses ASN (Autonomous System Numbers)"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$dnsmessage = "asn number"
  condition:
    any of them
}
