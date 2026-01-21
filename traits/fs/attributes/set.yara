// Migrated from malcontent: fs/attributes/set.yara

rule set_xattr: medium {
  meta:
    description = "set an extended file attribute value"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setxattr.2.html"

  strings:
$ref = "setxattr" fullword
  condition:
    any of them
}
