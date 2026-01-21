// Migrated from malcontent: exfil/stealer/password.yara

rule password_finder_mimipenguin: critical {
  meta:
    description = "Password finder/dumper, such as MimiPenguin"
    mbc         = "OB0009"
    attack      = "T1041"
    confidence  = "0.66"

  strings:
$base_lightdm     = "lightdm" fullword
    $base_apache2     = "apache2.conf" fullword
    $base_vsftpd      = "vsftpd" fullword
    $base_shadow      = "/etc/shadow"
    $base_gnome       = "gnome-keyring-da"
    $base_sshd_config = "sshd" fullword

    $extra_finder           = /\bFinder\b/
    $extra_password         = /\b[Pp]assword\b/
    $extra_password2        = /.[^\s]{0,32}-password/
    $extra_proc             = /\/proc\/.{0,3}\/maps/
    $not_basic_auth_example = /\w{0,32}\:[Pp]assword/
    $not_caddy              = "//starting caddy process"
    $not_datadog            = /[Dd]ata[Dd]og/
  condition:
    filesize < 2MB and 3 of ($base*) and any of ($extra*) and none of ($not*)
}

rule password_prompt: medium {
  meta:
    description = "prompts for a password"
    confidence  = "0.66"

  strings:
$isPasswordVisible = "isPasswordVisible"
  condition:
    filesize < 25MB and any of them
}

rule password_prompt_high: high {
  meta:
    description = "demands a password to be entered"
    confidence  = "0.66"

  strings:
$must = "password must be entered"
  condition:
    filesize < 25MB and any of them
}

rule verify_password: medium {
  meta:
    description = "verifies a password via unknown means"
    confidence  = "0.66"

  strings:
$verify = "verifyPassword"
  condition:
    filesize < 10MB and any of them
}
