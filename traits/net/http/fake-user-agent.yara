// Migrated from malcontent: net/http/fake-user-agent.yara

rule fake_user_agent_msie: high {
  meta:
    description = "pretends to be MSIE"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_MSIE         = /compatible; MSIE[ \;\(\)\w]{0,32}/
    $u_msie         = /compatible; msie[ \;\(\)\w]{0,32}/
    $u_msie2        = /MSIE 9.0\{/
    $not_access_log = "\"GET http://"
    $not_pixel      = "Pixel 5"
    $not_ipad       = "iPad Mini"
    $not_firefox    = "Firefox"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_windows_user_agent: high {
  meta:
    description = "pretends to be a Windows browser"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_Win64        = /Windows NT 10.0; Win64/
    $u_WinNT        = /Mozilla\/5.0 \(Windows NT/
    $not_access_log = "\"GET http://"
    $not_pixel      = "Pixel 5"
    $not_ipad       = "iPad Mini"
    $not_firefox    = "Firefox"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_khtml_val: high {
  meta:
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_khtml        = /KHTML, like Gecko\w Version\/\d+.\d+ Safari/
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_chrome: medium {
  meta:
    description = "pretends to be Chrome"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_chrome       = "(KHTML, like Gecko) Chrome"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_wordpress: high {
  meta:
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_wordpress    = "User-Agent: Internal Wordpress RPC connection"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_firefox: medium {
  meta:
    description = "pretends to be Firefox"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_gecko        = "Gecko/20"
    $not_nuclei     = "NUCLEI_TEMPLATES"
    $not_electron   = "ELECTRON_RUN_AS_NODE"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_netscape {
  meta:
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_mozilla      = "Mozilla/4" fullword
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule fake_user_agent_curl {
  meta:
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$u_curl         = "User-Agent: curl/"
    $not_access_log = "\"GET http://"
  condition:
    any of ($u_*) and none of ($not_*)
}

rule elf_faker_val: medium {
  meta:
    description = "Fake user agent"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$val = /Mozilla\/5[\.\w ]{4,64}/
  condition:
    uint32(0) == 1179403647 and $val
}

rule lowercase_mozilla_val: high {
  meta:
    description = "Fake user agent"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"

  strings:
$ref = /mozilla\/\d{1,2}\.[\.\w ]{0,32}/
  condition:
    $ref
}
