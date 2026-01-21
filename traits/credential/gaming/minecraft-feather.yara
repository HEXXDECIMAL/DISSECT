// Migrated from malcontent: credential/gaming/minecraft_feather.yara

rule minecraft_feather: high {
  meta:
    description = "accesses Minecraft credentials (Feather)"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"

  strings:
$ = ".feather"
    $ = "accounts.json"
  condition:
    all of them
}
