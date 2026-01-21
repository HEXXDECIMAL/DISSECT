// Migrated from malcontent: anti-static/packer/allatori_java.yara

rule allatori: high {
  meta:
    description = "packed with https://allatori.com/"
    confidence  = "0.66"
    filetypes   = "java"

  strings:
$demo = "ALLATORI"
  condition:
    filesize < 1MB and any of them
}

rule allatori_demo: critical {
  meta:
    description = "packed with demo copy of https://allatori.com/"
    confidence  = "0.66"
    filetypes   = "java"

  strings:
$demo = "ALLATORIxDEMO"
  condition:
    filesize < 1MB and any of them
}
