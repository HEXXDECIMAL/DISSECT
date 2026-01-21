// Migrated from malcontent: net/resolve/hostname-resolve.yara

rule gethostbyname {
  meta:
    description = "resolve network host name to IP address"
    capability  = "true"
    confidence  = "0.66"
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/gethostbyname"

  strings:
$gethostbyname2 = "gethostbyname" fullword
  condition:
    any of them
}

rule gethostbyname2 {
  meta:
    description = "resolve network host name to IP address"
    confidence  = "0.66"
    pledge      = "inet"
    ref         = "https://linux.die.net/man/3/gethostbyname2"

  strings:
$gethostbyname2 = "gethostbyname2" fullword
  condition:
    any of them
}

rule cannot_resolve {
  meta:
    description = "resolve network host name to IP address"
    confidence  = "0.66"

  strings:
$cannot_resolve = "cannot resolve"
    $resolveDNS     = "resolveDNS"
    $resolveDns     = "resolveDns"
  condition:
    any of them
}

rule net_hostlookup {
  meta:
    description = "resolve network host name to IP address"
    confidence  = "0.66"

  strings:
$net_lookup = "net.hostLookup"
    $hostip     = "LookupHostIP"
  condition:
    any of them
}

rule nodejs: medium {
  meta:
    description = "resolve network host name to IP address"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$resolve = "resolve4" fullword
  condition:
    filesize < 512KB and any of them
}

rule go_resolve: medium {
  meta:
    description = "resolve network host name to IP address"
    confidence  = "0.66"
    filetypes   = "elf,go,macho"

  strings:
$resolve = "LookupHost" fullword
  condition:
    any of them
}
