// Migrated from malcontent: impact/remote_access/daemon.yara

rule sudo_nohup: high {
  meta:
    description = "calls nohup sudo"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$nohup_sudo = /nohup sudo[ \.\/\w]{0,32}/
    $sudo_nohup = /sudo nohup[ \.\/\w]{0,32}/
  condition:
    any of them
}
