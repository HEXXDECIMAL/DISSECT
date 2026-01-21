// Migrated from malcontent: c2/connect/bash_tcp.yara

rule bash_tcp: high {
  meta:
    description = "sends data via /dev/tcp (bash)"
    mbc         = "OB0011"
    attack      = "T1071"
    confidence  = "0.66"
    filetypes   = "bash,sh,zsh"

  strings:
$ref = /[\w \-\\<]{0,32}>"{0,1}\/dev\/tcp\/[\$\{\/\:\-\w\"]{0,32}/
  condition:
    $ref
}
