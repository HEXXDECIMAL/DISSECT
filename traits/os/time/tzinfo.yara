// Migrated from malcontent: os/time/tzinfo.yara

rule tzinfo {
  meta:
    description = "Uses timezone information"
    capability  = "true"
    confidence  = "0.66"

  strings:
$tzinfo = "tzinfo" fullword
    $tzInfo = "tzInfo" fullword
    $tzdata = "tzdata" fullword
  condition:
    any of them
}
