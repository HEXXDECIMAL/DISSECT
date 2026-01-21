// Migrated from malcontent: net/ip/ip-resolve.yara

rule gethostbyaddr {
  meta:
    description = "resolves network hosts via IP address"
    mbc         = "C0001"
    confidence  = "0.66"
    ref         = "https://linux.die.net/man/3/gethostbyaddr"
    pledge      = "dns"

  strings:
$gethostbyname2 = "gethostbyaddr" fullword
    $ResolvHost     = "ResolvHost"
    $resolv_host    = "resolv_host"
    $ruby           = "Resolv.getaddress"
    $lookup_ip      = "LookupIP"
  condition:
    any of them
}

rule resolve_base64: high {
  meta:
    description = "resolves base64-encoded address"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$ref = /Resolv\.getaddress\(Base64\.decode64\(.{1,64}\)\)/
  condition:
    any of them
}
