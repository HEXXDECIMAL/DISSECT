// Migrated from malcontent: impact/remote_access/dll_injection.yara

rule dll_injection: high {
  meta:
    description = "injects a DLL into other processes"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$prog_rundll          = "rundll32"
    $f_RtlStackDbStackAdd = "RtlStackDbStackAdd"
  condition:
    any of ($prog*) and any of ($f*)
}

rule dll_injection_js: critical {
  meta:
    description = "injects a DLL into other processes from javascript"
    confidence  = "0.66"

  strings:
$f_child_proc = "require('child_process');"
    $f_fs         = "require('fs');"
  condition:
    filesize < 32KB and dll_injection and any of ($f*)
}
