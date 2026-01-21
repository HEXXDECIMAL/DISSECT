// Migrated from malcontent: credential/browser/chrome_cookies.yara

rule chrome_cookies: high {
  meta:
    description = "access Google Chrome Cookie files"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"

  strings:
$ref  = "/Google/Chrome"
    $ref2 = "/Cookies"
  condition:
    all of them
}
