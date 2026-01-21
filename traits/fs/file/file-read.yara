// Migrated from malcontent: fs/file/file-read.yara

rule go_file_read {
  meta:
    description = "reads files"
    capability  = "true"
    confidence  = "0.66"
    syscall     = "open,close"

  strings:
$read  = "os.(*File).Read"
    $other = "ReadFile"
  condition:
    any of them
}

rule node_file_read {
  meta:
    description = "reads files"
    confidence  = "0.66"
    syscall     = "open,close"

  strings:
$read = "fs.readFile"
  condition:
    any of them
}

rule python_read {
  meta:
    description = "reads files"
    confidence  = "0.66"

  strings:
$ref = /open\([\w\.'"]{1,64}\).read\(\)/
  condition:
    any of them
}

rule ruby_read {
  meta:
    description = "reads files"
    confidence  = "0.66"
    filetypes   = "rb"

  strings:
$ref = /File\.read\([\w\.'"]{1,64}\)/
  condition:
    any of them
}

rule python_file_read {
  meta:
    description = "opens a file for read"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$val = /open\([\"\w\.]{1,32}\, {0,2}["']r["']\)/
  condition:
    any of them
}

rule python_file_read_binary: medium {
  meta:
    description = "opens a binary file for read"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$val = /open\([\"\w\.]{1,32}\, {0,2}["']rb["']\)/
  condition:
    any of them
}
