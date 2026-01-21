// Migrated from malcontent: evasion/file/location/dev-mqueue.yara

rule dev_mqueue: medium {
  meta:
    description = "path reference within /dev/mqueue (world writeable)"
    confidence  = "0.66"

  strings:
$mqueue = /\/dev\/mqueue[%\w\.\-\/]{0,64}/
  condition:
    any of them
}
