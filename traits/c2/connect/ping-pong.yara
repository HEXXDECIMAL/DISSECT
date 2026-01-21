// Migrated from malcontent: c2/connect/ping_pong.yara

rule ping_pong: medium {
  meta:
    description = "sends PING/PONG packets, possibly to a C2"
    mbc         = "OB0011"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$ping   = "PING" fullword
    $pong   = "PONG" fullword
    $socket = "socket" fullword
  condition:
    filesize < 1MB and all of them
}
