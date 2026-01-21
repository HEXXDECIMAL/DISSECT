// Migrated from malcontent: evasion/bypass_security/macos/trusted-certs.yara

rule trusted_cert_manipulator: high {
  meta:
    description = "installs a trusted root certificate"
    confidence  = "0.66"

  strings:
$security         = "security"
    $add_trusted_cert = "add-trusted-cert"
    $not_certtool     = "PROGRAM:certtool"
    $not_private      = "/System/Library/PrivateFrameworks"
  condition:
    $security and $add_trusted_cert and none of ($not*)
}
