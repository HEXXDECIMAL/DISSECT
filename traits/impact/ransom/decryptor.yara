// Migrated from malcontent: impact/ransom/decryptor.yara

rule decryptor: medium {
  meta:
    description = "References 'decryptor'"
    mbc         = "OB0010"
    attack      = "T1486"
    confidence  = "0.66"

  strings:
$ref = "decryptor"
  condition:
    filesize < 20MB and any of them
}
