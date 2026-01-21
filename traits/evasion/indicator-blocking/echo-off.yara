// Migrated from malcontent: evasion/indicator_blocking/echo_off.yara

rule js_echo_off: high {
  meta:
    description = "runs a batch file and hides command output"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$ref   = "@echo off"
    $child = /require\(['"]child_process['"]\);/
  condition:
    filesize < 16KB and all of them
}
