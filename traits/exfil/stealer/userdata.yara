// Migrated from malcontent: exfil/stealer/userdata.yara

rule userdata_crawler: high {
  meta:
    description = "crawls directories looking for application data"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$crawlCookies = "crawlUserData"
    $appdata      = "appData"
  condition:
    filesize < 1MB and all of them
}
