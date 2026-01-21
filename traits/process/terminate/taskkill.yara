// Migrated from malcontent: process/terminate/taskkill.yara

rule taskkill: medium windows {
  meta:
    description = "kills tasks and/or processes"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$ref  = "taskkill" fullword
    $ref2 = "TASKKILL" fullword
  condition:
    any of them
}

rule taskkill_force: high windows {
  meta:
    description = "forcibly kills programs"
    mbc         = "C0039"
    confidence  = "0.66"

  strings:
$ref  = /taskkill \/IM .{0,32}\.exe \/F/
    $ref2 = /TASKKILL \/IM .{0,32}\.exe \/F/
  condition:
    any of them
}
