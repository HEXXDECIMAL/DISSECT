// Migrated from malcontent: persist/daemon/detach.yara

rule detach: medium {
  meta:
    description = "process detaches and daemonizes"
    confidence  = "0.66"

  strings:
$ref  = /[\w\/]{0,16}xdaemon/
    $ref2 = /[\w\/]{0,16}go-daemon/
    $ref3 = "RunInBackground"
  condition:
    any of them
}
