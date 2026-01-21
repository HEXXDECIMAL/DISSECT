// Migrated from malcontent: fs/path/usr-sbin-telnetd.yara

rule usr_sbin_telnetd: high {
  meta:
    description = "References /usr/sbin/telnetd"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref          = "/usr/sbin/telnetd"
    $not_dos2unix = "/usr/bin/dos2unix"
    $not_setfont  = "/usr/sbin/setfont"
  condition:
    $ref and none of ($not*)
}
