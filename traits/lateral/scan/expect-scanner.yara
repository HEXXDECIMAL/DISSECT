// Migrated from malcontent: lateral/scan/expect_scanner.yara

rule expect_spawn: high {
  meta:
    confidence  = "0.66"
    ref         = "https://cert.gov.ua/article/6123309"

  strings:
$expect     = "expect -"
    $s_cron     = "spawn su"
    $s_password = "password"
    $s_whoami   = "whoami"
  condition:
    $expect and any of ($s*)
}
