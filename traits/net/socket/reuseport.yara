// Migrated from malcontent: net/socket/reuseport.yara

rule reuseport: medium {
  meta:
    description = "reuse TCP/IP ports for listening and connecting"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$go        = "go-reuseport"
    $so_readdr = "SO_REUSEADDR"
    $so_report = "SO_REUSEPORT"
  condition:
    any of them
}
