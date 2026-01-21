// Migrated from malcontent: evasion/bypass_security/linux/pam.yara

rule pam_passwords: medium {
  meta:
    description = "contains password authentication module"
    confidence  = "0.66"

  strings:
$auth       = "pam_authenticate"
    $pass       = "password"
    $not_libpam = "Linux-PAM" fullword
    $not_sshd   = "OpenSSH" fullword
  condition:
    $auth and $pass and none of ($not*)
}
