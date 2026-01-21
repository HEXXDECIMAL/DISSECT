// Migrated from malcontent: discover/process/runtime_deps.yara

import "elf"
import "math"


rule tls_get_addr: medium {
  meta:
    description = "looks up thread private variables, may be used for loaded library discovery"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"
    ref         = "https://chao-tic.github.io/blog/2018/12/25/tls"

  strings:
$val = "__tls_get_addr" fullword
  condition:
    any of them
}

rule sus_dylib_tls_get_addr: high {
  meta:
    description = "suspicious runtime dependency resolution"
    mbc         = "E1057"
    attack      = "T1057"
    confidence  = "0.66"

  strings:
$val               = "__tls_get_addr" fullword
    $not_trampoline    = "__interceptor_trampoline"
    $not_glibc_private = "GLIBC_PRIVATE"
  condition:
    filesize < 500KB and elf.type == elf.ET_DYN and $val and none of ($not*) and math.entropy(1, filesize) >= 6
}
