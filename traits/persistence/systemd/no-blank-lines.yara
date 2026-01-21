// Migrated from malcontent: persist/systemd/no_blank_lines.yara

rule systemd_no_blank_lines: high {
  meta:
    confidence  = "0.66"
    ref         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    filetypes   = "service"

  strings:
$execstart  = "ExecStart"
    $not_blank  = "\n\n"
    $not_apport = "ExecStart=/usr/share/apport/apport"
  condition:
    filesize < 4096 and $execstart and none of ($not*)
}
