// Migrated from malcontent: discover/user/APPDATA.yara

rule APPDATA: windows low {
  meta:
    description = "Looks up the application data directory for the current user"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"

  strings:
$ref = "APPDATA" fullword
  condition:
    all of them
}

rule APPDATA_microsoft: windows medium {
  meta:
    description = "Looks up the 'Microsoft' application data directory for the current user"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"

  strings:
$ref  = "APPDATA" fullword
    $ref2 = "'Microsoft'"
  condition:
    all of them
}
