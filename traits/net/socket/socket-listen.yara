// Migrated from malcontent: net/socket/socket-listen.yara

rule listen: medium {
  meta:
    description = "listen on a socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    pledge      = "inet"
    syscall     = "accept"

  strings:
$socket   = "socket" fullword
    $listen   = "listen" fullword
    $accept   = "accept" fullword
    $accept64 = "accept64" fullword
  condition:
    2 of them
}

rule go_listen: medium {
  meta:
    description = "listen on a socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    pledge      = "inet"
    syscall     = "accept"
    filetypes   = "elf,go,macho"

  strings:
$net_listen = "net.Listen"
  condition:
    any of them
}

rule generic_listen_string: medium {
  meta:
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"

  strings:
$listen = /[Ll]istening on/
  condition:
    any of them
}

rule netcat_listener: medium {
  meta:
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    ref_nc_nvlp = "https://juggernaut-sec.com/docker-breakout-lpe/"

  strings:
$nc_nvlp = /nc -[a-z]{0,3}p/
  condition:
    any of them
}

rule ruby_listener: medium {
  meta:
    description = "listens at a TCP socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    filetypes   = "rb"

  strings:
$socket_tcp = "Socket.tcp_server"
  condition:
    any of them
}
