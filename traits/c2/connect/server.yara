// Migrated from malcontent: c2/connect/server.yara

rule connect_server: medium {
  meta:
    description = "connects to a server"
    mbc         = "OB0011"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$ = "connected to server" fullword
  condition:
    filesize < 1MB and any of them
}
