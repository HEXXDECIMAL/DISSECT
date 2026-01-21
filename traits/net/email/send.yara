// Migrated from malcontent: net/email/send.yara

rule SMTPClient_Send: medium windows {
  meta:
    description = "sends e-mail"
    capability  = "true"
    confidence  = "0.66"

  strings:
$send = "SMTPClient.Send("
    $smtp = "System.Net.Mail.SmtpClient("
  condition:
    any of them
}

rule SMTPClient_Send_creds: high windows {
  meta:
    description = "sends e-mail with a hardcoded credentials"
    confidence  = "0.66"

  strings:
$send = "SMTPClient.Send("
    $smtp = "System.Net.Mail.SmtpClient("
    $cred = "NetworkCredential"
  condition:
    filesize < 128KB and any of them
}
