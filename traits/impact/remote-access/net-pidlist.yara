// Migrated from malcontent: impact/remote_access/net_pidlist.yara

rule proc_listpids_and_curl: high macos {
  meta:
    description = "lists processes and uses curl"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$proc_listpids = "proc_listpids"
    $libcurl       = "libcurl"
  condition:
    all of them
}
