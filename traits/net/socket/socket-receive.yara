// Migrated from malcontent: net/socket/socket-receive.yara

rule recvmsg {
  meta:
    description = "receive a message from a socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    ref         = "https://linux.die.net/man/2/recvmsg"

  strings:
$recvmsg  = "recvmsg" fullword
    $recvfrom = "recvfrom" fullword
    $_recv    = "_recv" fullword
  condition:
    any of them
}

rule recv {
  meta:
    description = "receive a message to a socket"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    syscall     = "recv"
    ref         = "https://linux.die.net/man/2/recv"

  strings:
$send   = "recv" fullword
    $socket = "socket" fullword
  condition:
    all of them
}
