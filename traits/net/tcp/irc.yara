// Migrated from malcontent: net/tcp/irc.yara

rule irc_protocol: medium {
  meta:
    description = "Uses IRC (Internet Relay Chat)"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "inet"
    credit      = "Initially ported from https://github.com/jvoisin/php-malware-finder"

  strings:
$join    = "JOIN" fullword
    $mode    = "MODE" fullword
    $nick    = "NICK" fullword
    $notice  = "NOTICE" fullword
    $part    = "PART" fullword
    $pass    = "PASS" fullword
    $ping    = "PING" fullword
    $pong    = "PONG" fullword
    $privmsg = "PRIVMSG" fullword
    $user    = "USER" fullword
  condition:
    $nick and $user and 2 of them
}

rule small_elf_irc: high {
  meta:
    description = "Uses IRC (Internet Relay Chat)"
    confidence  = "0.66"

  condition:
    uint32(0) == 1179403647 and filesize < 10MB and irc_protocol
}
