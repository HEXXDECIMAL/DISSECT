// Migrated from malcontent: c2/discovery/dga.yara

rule dga_url: high {
  meta:
    description = "References Domain Generation Algorithm for C2 discovery"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ = "dgaURL" fullword
    $ = "dgaUrl" fullword
    $ = "dgaurl" fullword
  condition:
    any of them
}
