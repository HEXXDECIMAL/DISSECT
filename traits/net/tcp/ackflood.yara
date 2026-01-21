// Migrated from malcontent: net/tcp/ackflood.yara

rule ackflood: medium {
  meta:
    description = "References ACK flooding"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref = "ackflood" fullword
  condition:
    any of them
}
