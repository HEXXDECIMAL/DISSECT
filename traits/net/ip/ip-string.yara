// Migrated from malcontent: net/ip/ip-string.yara

rule inet_ntoa: medium {
  meta:
    description = "converts IP address from byte to string"
    mbc         = "C0001"
    confidence  = "0.66"
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/inet_ntoa"

  strings:
$ref  = "inet_ntoa" fullword
    $ref2 = "inet_ntop" fullword
  condition:
    any of them
}
