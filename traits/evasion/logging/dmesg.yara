// Migrated from malcontent: evasion/logging/dmesg.yara

rule dmesg_clear: high linux {
  meta:
    description = "clears the kernel log ring buffer"
    confidence  = "0.66"

  strings:
$ = "dmesg -C" fullword
    $ = "dmesg -c" fullword
    $ = "dmesg --clear" fullword
    $ = "dmesg --read-clear" fullword
  condition:
    filesize < 100MB and any of them
}

rule dmesg_clear_override: override {
  meta:
    confidence  = "0.66"
    dmesg_clear = "medium"

  strings:
$Kselftest = "Kselftest" fullword
  condition:
    any of them
}
