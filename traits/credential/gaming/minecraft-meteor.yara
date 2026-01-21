// Migrated from malcontent: credential/gaming/minecraft_meteor.yara

rule minecraft_meteor: high {
  meta:
    description = "accesses Minecraft credentials (Meteor)"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"

  strings:
$ = ".meteor-client"
    $ = "accounts.nbt"
  condition:
    all of them
}
