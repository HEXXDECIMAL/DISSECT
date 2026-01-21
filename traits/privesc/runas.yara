// Migrated from malcontent: privesc/runas.yara

rule runas_admin: high {
  meta:
    description = "Uses RunAs to execute code as another user"
    confidence  = "0.66"

  strings:
$start_process = /[\w \'\:\\\"\-\%]{0,32}Start-Process.{0,32}RunAs[\w \'\:\\\"\-\%]{0,32}/
    $py_shell_exec = "ShellExecuteW(None, \"runas\""
  condition:
    any of them
}

rule py_runas_admin: high {
  meta:
    description = "Uses RunAs to execute itself as another user"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$double = "\"runas\", sys.executable,"
    $single = "'runas', sys.executable,"
  condition:
    any of them
}
