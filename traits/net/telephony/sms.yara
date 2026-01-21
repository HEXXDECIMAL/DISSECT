// Migrated from malcontent: net/telephony/sms.yara

rule send_sms: medium {
  meta:
    description = "sends SMS messages"
    capability  = "true"
    confidence  = "0.66"

  strings:
$send = "send sms"
    $imsi = "imsi"
  condition:
    filesize < 2MB and all of them
}

rule recv_sms: medium {
  meta:
    description = "receives SMS messages"
    confidence  = "0.66"

  strings:
$send = "recv sms"
    $imsi = "imsi"
  condition:
    filesize < 2MB and all of them
}
