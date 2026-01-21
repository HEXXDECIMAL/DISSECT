// Migrated from malcontent: persist/systemd/out_of_dependency_tree.yara

rule systemd_not_in_dependency_tree: medium {
  meta:
    description = "Relies on nothing, nothing relies on it"
    confidence  = "0.66"
    filetypes   = "service"

  strings:
$execstart        = "ExecStart="
    $expect_after     = /After=\w/
    $expect_before    = /Before=\w{1,128}/
    $expect_requires  = /Requires=\w/
    $expect_condition = "ConditionPath"
    $expect_oneshot   = "Type=oneshot"
    $expect_default   = "DefaultDependencies=no"
    $expect_env       = "EnvironmentFile="
    $expect_bus       = "BusName="
    $expect_idle      = "Type=idle"
    $expect_systemd   = "ExecStart=systemd-"
  condition:
    filesize < 4096 and $execstart and none of ($expect_*)
}

rule type_forking_not_in_dep_tree: high {
  meta:
    description = "forking service that nothing relies on"
    confidence  = "0.66"

  strings:
$forking       = "Type=forking"
    $expect_after  = /After=\w/
    $expect_before = /Before=\w{1,128}/
  condition:
    filesize < 4096 and $forking and none of ($expect*)
}
