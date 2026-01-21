// Migrated from malcontent: persist/systemd/no_docs_or_comments.yara

rule systemd_no_comments_or_documentation: medium {
  meta:
    description = "systemd unit is undocumented"
    confidence  = "0.66"
    ref         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    filetypes   = "service"

  strings:
$execstart          = "ExecStart="
    $ex_comment         = "# "
    $ex_documentation   = "Documentation="
    $ex_requires_socket = /Requires=.{0,64}socket/
    $ex_condition_path  = "Condition"
    $ex_after           = "After="
    $ex_systemd         = "ExecStart=systemd-"
    $ex_output          = "StandardOutput="
  condition:
    filesize < 4KB and $execstart and none of ($ex_*)
}
