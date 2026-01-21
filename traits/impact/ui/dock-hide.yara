// Migrated from malcontent: impact/ui/dock-hide.yara

rule dock_hider: high {
  meta:
    description = "hides application from Dock"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"

  strings:
$hideDock            = "hideDock"
    $applicationWillHide = "applicationWillHide"
  condition:
    any of them
}
