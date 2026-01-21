// Migrated from malcontent: fs/overwrite.yara

rule background_dd: high {
  meta:
    confidence  = "0.66"
    ref         = "https://cert.gov.ua/article/6123309"

  strings:
$rm_rf_bg = /dd if=[\/\w\.\-\" \=]{0,64} &[^&]/
  condition:
    filesize < 10485760 and all of them
}
