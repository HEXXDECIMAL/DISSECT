// Migrated from malcontent: exfil/stealer/vmware.yara

import "math"


rule vmware_dump_files: high windows {
  meta:
    description = "may steal VMware state files"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$app_data = "Application Data"
    $VMware   = "VMware"
    $dmp      = "*.dmp"
  condition:
    filesize < 256KB and all of them and math.max(@VMware, @dmp) - math.min(@VMware, @dmp) <= 16
}
