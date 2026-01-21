// Migrated from malcontent: anti-static/elf/multiple.yara

import "elf"


rule multiple_elf: medium {
  meta:
    description = "multiple ELF binaries within an ELF binary"
    confidence  = "0.66"
    filetypes   = "elf"

  strings:
$elf_head = "\x7fELF"
  condition:
    uint32(0) == 1179403647 and #elf_head > 1
}
