// Migrated from malcontent: anti-static/packer/pe.yara

import "math"


rule pe_packed: high windows {
  meta:
    description = "packed PE file (Windows EXE) with high entropy (>7)"
    confidence  = "0.66"
    filetype    = "exe,pe"

  condition:
    uint16(0) == 0x5a4d and math.entropy(0, filesize) > 7
}
