// Migrated from malcontent: credential/sniffer/bpf.yara

rule sniffer_bpf: medium {
  meta:
    description = "BPF (Berkeley Packet Filter)"
    mbc         = "OB0004"
    attack      = "T1555"
    confidence  = "0.66"
    capability  = "CAP_SYS_BPF"

  strings:
$ref2 = "/dev/bpf"
    $ref3 = "SetBPF" fullword
    $ref4 = "SetsockoptSockFprog"
  condition:
    any of them
}
