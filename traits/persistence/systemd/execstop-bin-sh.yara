// Migrated from malcontent: persist/systemd/execstop-bin-sh.yara

rule bin_sh_execstop: medium {
  meta:
    description = "Runs shell script at stop"
    confidence  = "0.66"
    ref         = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
    filetypes   = "service"

  strings:
$execstop = /ExecStop=\/bin\/sh\/[\w\. \-\'\"]{0,64}/
  condition:
    filesize < 4KB and $execstop
}
