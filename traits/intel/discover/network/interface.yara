// Migrated from malcontent: discover/network/interface.yara

rule bsd_if {
  meta:
    description = "get network interfaces by name or index"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$if_nametoindex   = "if_nametoindex" fullword
    $if_indextoname   = "if_indextoname" fullword
    $if_nameindex     = "if_nameindex" fullword
    $if_freenameindex = "if_freenameindex" fullword
  condition:
    any of them
}

rule macos_scnetwork {
  meta:
    description = "retrieve network device information"
    mbc         = "E1016"
    attack      = "T1016"
    confidence  = "0.66"

  strings:
$ref = "SCNetworkServiceGet" fullword
  condition:
    any of them
}
