// Migrated from malcontent: net/socket/multiplexing.yara

rule go_nps_mux: high {
  meta:
    description = "Uses github.com/smallbutstrong/nps-mux to multiplex network connections"
    mbc         = "C0001"
    attack      = "T1071"
    confidence  = "0.66"
    filetypes   = "elf,go,macho"

  strings:
$ref1 = ").ReturnBucket"
    $ref2 = ").NewTrafficControl"
    $ref3 = ").SetReadDeadline"
  condition:
    all of them
}
