// Migrated from malcontent: net/tcp/raw.yara

rule tcpraw: medium {
  meta:
    description = "Supports raw TCP packets"
    capability  = "true"
    confidence  = "0.66"

  strings:
$tcpraw = "tcpraw" fullword
  condition:
    filesize < 10MB and any of them
}
