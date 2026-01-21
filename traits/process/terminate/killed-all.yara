// Migrated from malcontent: process/terminate/killed_all.yara

rule killed_all: medium {
  meta:
    description = "References 'killed all'"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$ref = /killed all[\w ]+/
  condition:
    any of them
}

rule killed_format: medium {
  meta:
    description = "References 'killed %d'"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$ref = /[Kk]illed %d/
  condition:
    any of them
}
