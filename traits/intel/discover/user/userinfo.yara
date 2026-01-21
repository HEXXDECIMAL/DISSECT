// Migrated from malcontent: discover/user/userinfo.yara

rule userinfo: medium {
  meta:
    description = "returns user info for the current process"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"
    syscall     = "getuid"
    filetypes   = "js,ts"

  strings:
$ref  = "os.userInfo()"
    $ref2 = "os.homedir"
  condition:
    any of them
}
