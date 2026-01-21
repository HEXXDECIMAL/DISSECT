// Migrated from malcontent: impact/remote_access/socat.yara

rule socat_backdoor: high {
  meta:
    description = "possible socat backdoor"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$socat     = "socat" fullword
    $bin_bash  = "/bin/bash"
    $pty       = "pty" fullword
    $not_usage = "usage: "
  condition:
    $socat and $bin_bash and $pty and none of ($not*)
}
