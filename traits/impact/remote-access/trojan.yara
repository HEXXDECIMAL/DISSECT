// Migrated from malcontent: impact/remote_access/trojan.yara

rule trojan_ref: medium {
  meta:
    description = "References a Trojan"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$s_trojan = "trojan" fullword
    $s_Trojan = "Trojan"
  condition:
    any of ($s*)
}

rule trojan_ref_leet: high {
  meta:
    description = "References a Trojan"
    confidence  = "0.66"

  strings:
$s_tr0jan = "tr0jan" fullword
  condition:
    any of ($s*)
}

rule trojan_ref_loaded: high {
  meta:
    description = "References a loaded Trojan"
    confidence  = "0.66"

  strings:
$s_tr0jan = "Trojan run" fullword
  condition:
    filesize < 1MB and any of ($s*)
}
