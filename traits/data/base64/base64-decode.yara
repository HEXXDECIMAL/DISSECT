// Migrated from malcontent: data/base64/base64-decode.yara

rule base64_decode: medium python {
  meta:
    description = "decode base64 strings"
    capability  = "true"
    confidence  = "0.66"
    ref         = "https://docs.python.org/3/library/base64.html"
    filetypes   = "py"

  strings:
$b64decode = "b64decode"
  condition:
    any of them
}

rule py_base64_decode: medium php {
  meta:
    description = "decode base64 strings"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$b64decode = "base64_decode"
  condition:
    any of them
}

rule js_base64_decode: medium js {
  meta:
    description = "decode base64 strings"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$atob = "atob("
  condition:
    any of them
}

rule js_double_base64_decode: critical js {
  meta:
    description = "double-decodes base64 strings"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$atob = "atob(atob("
  condition:
    any of them
}

rule ruby_base64_decode: medium ruby {
  meta:
    description = "decode base64 strings"
    confidence  = "0.66"
    filetypes   = "rb"

  strings:
$b64decode = /[\._]decode64/
  condition:
    any of them
}

rule urlsafe_decode64: medium ruby {
  meta:
    description = "decode base64 strings"
    confidence  = "0.66"
    ref         = "https://ruby-doc.org/3.3.0/stdlibs/base64/Base64.html"
    filetypes   = "rb"

  strings:
$urlsafe_decode64_ruby = "urlsafe_decode64"
  condition:
    any of them
}

rule powershell_decode: medium {
  meta:
    description = "decode base64 strings"
    confidence  = "0.66"
    ref         = "https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-8.0"
    filetypes   = "ps1"

  strings:
$ref = /System\.Convert[\]: ]+FromBase64String/ ascii
  condition:
    any of them
}
