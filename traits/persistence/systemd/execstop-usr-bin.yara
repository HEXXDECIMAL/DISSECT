// Migrated from malcontent: persist/systemd/execstop-usr-bin.yara

rule usr_bin_execstop: medium {
  meta:
    description = "Runs program from /usr/bin at stop"
    confidence  = "0.66"
    ref         = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
    filetypes   = "service"

  strings:
$execstop = /ExecStop=\/usr\/bin\/[\w\.]{0,32}/
    $finalrd  = "ExecStop=/usr/bin/finalrd"
  condition:
    filesize < 4KB and $execstop and not $finalrd
}
