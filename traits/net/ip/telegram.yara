// Migrated from malcontent: c2/addr/telegram.yara

rule telegram: medium {
  meta:
    mbc         = "C0001"
    confidence  = "0.66"
    discription = "may report back to 'Telegram'"

  strings:
$t1 = "telegram.org"
    $t2 = "Telegram"
  condition:
    any of them
}
