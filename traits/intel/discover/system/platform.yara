// Migrated from malcontent: discover/system/platform.yara

rule uname {
  meta:
    description = "system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    pledge      = "sysctl"
    syscall     = "sysctl"
    ref         = "https://man7.org/linux/man-pages/man1/uname.1.html"

  strings:
$uname  = "uname" fullword
    $uname2 = "syscall.Uname" fullword
    $uname3 = "unix.Uname"
  condition:
    any of them
}

rule uname_a: medium {
  meta:
    description = "gets full system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$uname_a = /uname -a\w{0,2}/ fullword
  condition:
    any of them
}

rule os_release: medium {
  meta:
    description = "operating-system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    pledge      = "sysctl"
    syscall     = "sysctl"
    ref         = "https://developer.apple.com/documentation/os/1524245-os_release"

  strings:
$ref  = "os_release" fullword
    $ref2 = "osInfo" fullword
  condition:
    any of them
}

rule os_type: low {
  meta:
    description = "operating-system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    pledge      = "sysctl"
    syscall     = "sysctl"
    ref         = "https://developer.apple.com/documentation/os/1524245-os_release"

  strings:
$ref3 = "$OSTYPE" fullword
  condition:
    any of them
}

rule macos_platform_check: medium {
  meta:
    description = "platform check"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    pledge      = "sysctl"
    syscall     = "sysctl"
    ref         = "https://developer.apple.com/documentation/os/1524245-os_release"

  strings:
$ref  = "isPlatformOrVariantPlatformVersionAtLeast" fullword
    $ref2 = "/System/Library/CoreServices/SystemVersion.plist" fullword
    $ref3 = "IOPlatformExpertDevice" fullword
  condition:
    any of them
}

rule python_platform: medium {
  meta:
    description = "system platform identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    ref         = "https://docs.python.org/3/library/platform.html"
    filetypes   = "py"

  strings:
$ref  = "platform.dist()"
    $ref2 = "platform.platform()"
    $ref3 = "sys.platform"
    $ref4 = "platform.system()"
  condition:
    any of them
}

rule browser_platform: medium {
  meta:
    description = "system platform identification via browser user-agent"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"

  strings:
$ref  = "userAgentData"
    $ref2 = "platformVersion"
  condition:
    all of them
}

rule npm_uname: medium {
  meta:
    description = "get system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    ref         = "https://nodejs.org/api/process.html"
    filetypes   = "js,ts"

  strings:
$ = "process.platform"
    $ = "process.arch"
    $ = "process.versions"
    $ = "os.platform()"
    $ = "os.arch()"
    $ = "os.release()"
    $ = "os.type()"
  condition:
    any of them
}

rule ruby_uname: medium ruby {
  meta:
    description = "get system identification"
    mbc         = "E1082"
    attack      = "T1082"
    confidence  = "0.66"
    filetypes   = "rb"

  strings:
$ = "CONFIG['host_os']"
    $ = "RUBY_PLATFORM"
  condition:
    any of them
}
