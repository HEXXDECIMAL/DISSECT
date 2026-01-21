// Migrated from malcontent: evasion/bypass_security/macos/tcc.yara

rule macos_tcc_db: high macos {
  meta:
    description = "access TCC (Transparency, Consent, and Control) database"
    confidence  = "0.66"

  strings:
$com_apple_TCC = "com.apple.TCC/TCC.db"
  condition:
    filesize < 100MB and $com_apple_TCC
}

rule known_macos_tcc_db: override macos {
  meta:
    description = "known user"
    confidence  = "0.66"
    macos_tcc_db = "medium"

  strings:
$arc     = "WelcomeToArc"
    $mdm     = "MDMOverrides.plist"
    $elastic = "co.elastic.systemextension"
  condition:
    filesize < 100MB and any of them
}
