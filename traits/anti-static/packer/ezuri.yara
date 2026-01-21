// Migrated from malcontent: anti-static/packer/ezuri.yara

rule ezuri: critical {
  meta:
    description = "packed with Ezuri (AES)"
    confidence  = "0.66"
    hash        = "3020810ea859787a9730de3df822caad3178a7179d587d6a96e303a3c159e714"
    filetypes   = "elf,macho"

  strings:
$runFromMemory = "main.runFromMemory" fullword
    $aesDesc       = "main.aesDec" fullword
    $ezuri         = "ezuri" fullword
    $main_iv       = "_main.iv" fullword
  condition:
    filesize > 50KB and filesize < 5MB and 2 of them
}
