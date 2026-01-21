// Migrated from malcontent: os/time/clock-convert.yara

rule bsd_time_conversion: harmless {
  meta:
    confidence  = "0.66"

  strings:
$asctime   = "asctime" fullword
    $ctime     = "ctime" fullword
    $difftime  = "difftime" fullword
    $gmtime    = "gmtime" fullword
    $localtime = "localtime" fullword
    $mktime    = "mktime" fullword
    $timegm    = "timegm" fullword
  condition:
    any of them
}
