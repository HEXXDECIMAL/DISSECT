// Migrated from malcontent: net/url/embedded.yara

rule https_url {
  meta:
    description = "contains embedded HTTPS URLs"
    capability  = "true"
    confidence  = "0.66"

  strings:
$ref       = /https:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $not_apple = "https://www.apple.com/appleca/"
  condition:
    $ref and none of ($not*)
}

rule http_url {
  meta:
    description = "contains embedded HTTP URLs"
    confidence  = "0.66"

  strings:
$ref       = /http:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $not_apple = "http://crl.apple.com/"
  condition:
    $ref and none of ($not*)
}

rule ftp_url {
  meta:
    description = "contains embedded FTP URLs"
    confidence  = "0.66"

  strings:
$ref = /ftp:\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}

rule ssh_url {
  meta:
    description = "contains embedded URLs"
    confidence  = "0.66"

  strings:
$ref = /ssh:\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}

rule http_url_with_php: medium {
  meta:
    description = "contains hardcoded PHP endpoint"
    confidence  = "0.66"

  strings:
$php_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.php/
    $php_question = /[\.\w\-\_\/:]{0,160}\.php\?[\w\-@\=]{0,32}/
    $php_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.php/
  condition:
    any of ($php*)
}

rule http_url_with_asp: medium {
  meta:
    description = "contains hardcoded ASP endpoint"
    confidence  = "0.66"

  strings:
$asp_url      = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.asp/
    $asp_question = /[\.\w\-\_\/:]{0,160}\.asp\?[\w\-@\=]{0,32}/
    $asp_c        = /https*:\/\/%s\/[\w\/\-\_]{0,160}.asp/
  condition:
    any of ($asp*)
}
