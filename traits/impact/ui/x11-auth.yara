// Migrated from malcontent: impact/ui/x11-auth.yara

rule x11_refs: medium {
  meta:
    description = "X Window System client authentication"
    mbc         = "OB0010"
    attack      = "T1498"
    confidence  = "0.66"
    ref         = "https://en.wikipedia.org/wiki/X_Window_authorization"

  strings:
$cookie = "MIT-MAGIC-COOKIE-1" fullword
    $xauth  = "xauth" fullword
  condition:
    any of them
}
