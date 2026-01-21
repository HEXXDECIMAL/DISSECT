// Migrated from malcontent: discover/user/username-get.yara

rule getlogin {
  meta:
    description = "get login name"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"
    syscall     = "getlogin"
    pledge      = "id"
    ref         = "https://linux.die.net/man/3/getlogin"

  strings:
$ref  = "getlogin" fullword
    $ref2 = "getpass.getuser" fullword
  condition:
    any of them
}

rule whoami: medium {
  meta:
    description = "returns the user name running this process"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"
    syscall     = "getuid"
    ref         = "https://man7.org/linux/man-pages/man1/whoami.1.html"

  strings:
$ref  = "whoami" fullword
    $ref2 = "NSUserName" fullword
  condition:
    any of them
}

rule user_pythonSetup {
  meta:
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"

  strings:
$if_distutils  = /from distutils.core import .{0,32}setup/
    $if_setuptools = /from setuptools import .{0,32}setup/
    $i_setuptools  = "import setuptools"
    $setup         = "setup("

    $not_setup_example = ">>> setup("
    $not_setup_todict  = "setup(**config.todict()"
    $not_import_quoted = "\"from setuptools import setup"
    $not_setup_quoted  = "\"setup(name="
    $not_distutils     = "from distutils.errors import"
  condition:
    filesize < 128KB and $setup and any of ($i*) and none of ($not*)
}

rule pysetup_gets_login: high {
  meta:
    description = "Python library installer gets login information"
    mbc         = "E1033"
    attack      = "T1033"
    confidence  = "0.66"
    filetypes   = "py"

  strings:
$ref  = "os.getlogin" fullword
    $ref2 = "getpass.getuser" fullword
    $ref3 = "whoami" fullword
  condition:
    user_pythonSetup and any of them
}
