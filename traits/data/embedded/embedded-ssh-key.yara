// Migrated from malcontent: data/embedded/embedded-ssh-key.yara

rule ssh_public_key: high {
  meta:
    description = "contains SSH public key"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://unfinished.bike/qubitstrike-and-diamorphine-linux-kernel-rootkits-go-mainstream"

  strings:
$ssh_rsa = /ssh-[dr]sa [\w\+\/\=]{0,1024} [\w\-\.]{0,32}\@[\w\.\-]{1,64}/
  condition:
    any of them
}

rule windows_ssh_public_key: critical {
  meta:
    description = "contains SSH public key generated from a Windows desktop"
    confidence  = "0.66"

  strings:
$ssh_rsa = /ssh-[dr]sa [\w\+\/\=]{0,1024} [\w\-\.]{0,32}\@DESKTOP-[\w\.\-]{1,64}/
  condition:
    any of them
}
