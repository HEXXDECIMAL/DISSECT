// Migrated from malcontent: c2/addr/discord.yara

rule discord: medium {
  meta:
    description = "may report back to 'Discord'"
    mbc         = "C0001"
    confidence  = "0.66"

  strings:
$t1 = "discordapp.com"
    $t2 = "Discord"
  condition:
    any of them
}
