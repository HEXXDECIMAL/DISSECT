// Migrated from malcontent: discover/user/dscl.yara

rule dscl_caller: medium {
  meta:
    description = "Calls dscl (Directory Service command line utility)"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"

  strings:
$dscl_local     = /dscl +\. +-\w{1,128}/
    $dsenableroot   = "dsenableroot"
    $not_read_users = "dscl . -read /Users/"
  condition:
    filesize < 131072 and any of ($d*) and none of ($not*)
}
