// Migrated from malcontent: evasion/bypass_security/macos/sip.yara

rule csrutil_user: medium {
  meta:
    description = "uses csrutil"
    confidence  = "0.66"

  strings:
$csrutil     = "csrutil"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_program = "@(#)PROGRAM:"
    $not_verbose = "CSRUTIL_VERBOSE"
    $not_mdm     = "com.kandji.profile.mdmprofile"
  condition:
    $csrutil and none of ($not_*)
}
