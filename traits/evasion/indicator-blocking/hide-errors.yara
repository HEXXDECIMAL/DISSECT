// Migrated from malcontent: evasion/indicator_blocking/hide_errors.yara

rule php_suppressed_include: high {
  meta:
    description = "Includes a file, suppressing errors"
    confidence  = "0.66"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"
    filetypes   = "php"

  strings:
$php           = "<?php"
    $include       = /@\s*include\s*/
    $not_snippet   = "snippet" fullword
    $not_copyright = "copyright" fullword
  condition:
    filesize < 5242880 and $php and $include and none of ($not*)
}
