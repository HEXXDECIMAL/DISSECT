// Migrated from malcontent: credential/browser/firefox-cookies.yara

rule firefox_cookies: high {
  meta:
    description = "access Firefox cookies"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"

  strings:
$firefox      = "Firefox"
    $fcookie      = "cookies.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"
  condition:
    filesize < 100MB and all of ($f*) and none of ($not*)
}
