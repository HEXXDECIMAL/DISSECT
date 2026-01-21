// Migrated from malcontent: anti-static/macho/footer.yara

import "math"


rule anti_static_macho {
  meta:
    confidence  = "0.66"

  condition:
    (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178)
}

rule high_entropy_trailer: high {
  meta:
    description = "higher-entropy machO trailer (normally NULL) - possible viral infection"
    confidence  = "0.66"
    ref         = "https://www.virusbulletin.com/virusbulletin/2013/06/multiplatform-madness"
    filetypes   = "macho"

  strings:
$page_zero = "_PAGEZERO"
  condition:
    filesize < 10MB and anti_static_macho and $page_zero and math.entropy(filesize - 1024, filesize - 1) >= 4
}
