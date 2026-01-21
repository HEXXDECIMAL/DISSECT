// Migrated from malcontent: persist/cron/etc_cron_d.yara

rule cron_d_user: high {
  meta:
    description = "Uses /etc/cron.d to persist"
    confidence  = "0.66"

  strings:
$c_etc_crontab = /\/etc\/cron\.d\/[\w\.\-\%\/]{1,16}/

    $not_usage = "usage: cron"
  condition:
    filesize < 52428800 and any of ($c*) and none of ($not*)
}
