// Migrated from malcontent: credential/browser/firefox-formhistory.yara

rule firefox_history: high {
  meta:
    description = "access Firefox form history, which contains passwords"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"

  strings:
$firefox      = "Firefox"
    $formhist     = "formhistory.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"
  condition:
    filesize < 100MB and all of ($f*) and none of ($not*)
}
