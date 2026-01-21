// Migrated from malcontent: credential/ssh/ssh_authorized_hosts.yara

rule ssh_authorized_hosts: medium {
  meta:
    description = "accesses SSH authorized_keys files"
    mbc         = "OB0004"
    attack      = "T1552.004"
    confidence  = "0.66"

  strings:
$ref              = ".ssh"
    $authorized_hosts = /[\/\.\$\%]{0,32}authorized_keys/
  condition:
    all of them
}
