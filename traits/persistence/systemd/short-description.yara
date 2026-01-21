// Migrated from malcontent: persist/systemd/short-description.yara

rule systemd_short_description {
  meta:
    description = "Short or no description"
    confidence  = "0.66"
    filetypes   = "service"

  strings:
$execstart  = "ExecStart="
    $short_desc = /Description=\w{,4}/ fullword
  condition:
    filesize < 4096 and all of them
}
