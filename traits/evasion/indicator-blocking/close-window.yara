// Migrated from malcontent: evasion/indicator_blocking/close_window.yara

rule tell_terminal_to_close: high {
  meta:
    description = "closes Terminal window"
    confidence  = "0.66"

  strings:
$close = "tell application \"Terminal\" to close first window"
  condition:
    filesize < 10MB and all of them
}
