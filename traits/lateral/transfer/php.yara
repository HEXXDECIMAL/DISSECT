// Migrated from malcontent: c2/tool_transfer/php.yara

rule php_copy_url: high {
  meta:
    confidence  = "0.66"
    ref         = "kinsing"
    filetypes   = "php"

  strings:
$php  = "<?php"
    $copy = /copy\([\'\"]http/
  condition:
    all of them
}
