// Migrated from malcontent: credential/ssh/sshd.yara

rule sshd: medium {
  meta:
    description = "Mentions SSHD"
    mbc         = "OB0004"
    attack      = "T1552.004"
    confidence  = "0.66"

  strings:
$ref = "sshd" fullword
  condition:
    $ref
}

rule sshd_path_value: high {
  meta:
    description = "Mentions the SSH daemon by path"
    confidence  = "0.66"

  strings:
$ref = "/usr/bin/sshd" fullword
  condition:
    $ref
}

rule sshd_net: high {
  meta:
    description = "Mentions SSHD network processes"
    confidence  = "0.66"

  strings:
$ref  = "sshd: [net]"
    $ref2 = "sshd: [accepted]"
  condition:
    any of them
}

rule sshd_proc: high {
  meta:
    description = "Mentions SSHD proces"
    confidence  = "0.66"

  strings:
$ref  = "sshdproc"
    $ref2 = "sshd_proc"
  condition:
    filesize < 1MB and any of them
}
