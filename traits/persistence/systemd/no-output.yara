// Migrated from malcontent: persist/systemd/no_output.yara

rule systemd_no_output: high {
  meta:
    description = "Discards all logging output"
    confidence  = "0.66"
    filetypes   = "service"

  strings:
$discard_stdout = "StandardOutput=null"
    $discard_stderr = "StandardError=null"
    $not_input_null = "StandardInput=null"
    $not_syslog     = "syslog"
    $not_fwmgr      = "ExecStart=/usr/bin/fwupdmgr"
  condition:
    filesize < 4KB and all of ($discard*) and none of ($not*)
}
