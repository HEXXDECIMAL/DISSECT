// Migrated from malcontent: credential/browser/chromium_credit_cards.yara

rule chromium_credit_cards: critical {
  meta:
    description = "Gets Chromium credit card information"
    mbc         = "OB0004"
    attack      = "T1555.003"
    confidence  = "0.66"

  strings:
$web_data      = "Web Data"
    $encrypted_key = "credit_cards"
    $c             = "Chrome"
    $c2            = "Chromium"
    $not_chromium  = "CHROMIUM_TIMESTAMP"
  condition:
    filesize < 25MB and any of ($c*) and $web_data and $encrypted_key and none of ($not*)
}
