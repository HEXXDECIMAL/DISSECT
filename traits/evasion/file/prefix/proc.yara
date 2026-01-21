// Migrated from malcontent: evasion/file/prefix/proc.yara

rule hidden_proc: high linux {
  meta:
    description = "references a hidden path within /proc"
    confidence  = "0.66"

  strings:
$hidden_proc = /\/proc\/\.\w{1,4}/ fullword
  condition:
    filesize < 10MB and all of them
}
