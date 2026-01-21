// Migrated from malcontent: exfil/npm.yara

rule package_scripts {
  meta:
    confidence  = "0.66"

  strings:
$npm_name        = /"name":/
    $npm_version     = /"version":/
    $npm_description = /"description":/
    mbc         = "OB0009"
    attack      = "T1041"
    $npm_lint        = /"lint":/
    $npm_test        = /"test":/
    $npm_postversion = /"postversion":/
    $npm_postinstall = /"postinstall":/
    $scripts         = /"scripts":/
  condition:
    filesize < 32KB and 3 of ($npm*) and $scripts
}

rule npm_fetcher: high {
  meta:
    description = "npm installer makes accesses external URLs"
    confidence  = "0.66"

  strings:
$fetch = /"(curl|wget) /
    $url   = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
  condition:
    package_scripts and $fetch and $url
}

rule npm_dev_tcp: critical {
  meta:
    description = "npm installer makes accesses external hosts via /dev/tcp"
    confidence  = "0.66"

  strings:
$dev_tcp = /\/dev\/tcp\/[\w\.\/]{0,32}/
  condition:
    package_scripts and $dev_tcp
}

rule npm_ping: critical {
  meta:
    description = "npm installer makes accesses external hosts via ping"
    confidence  = "0.66"

  strings:
$ping = /ping -\w [\w\-\. \$]{0,63}/
  condition:
    package_scripts and $ping
}

rule npm_sensitive_files: high {
  meta:
    description = "npm installer accesses system information"
    confidence  = "0.66"

  strings:
$ = "/proc/version"
    $ = "/proc/net/fib_trie"
    $ = "/proc/net/if_inet6"
    $ = "/etc/shadow"
    $ = "/etc/hosts"
    $ = "/etc/passwd"
  condition:
    package_scripts and any of them
}

rule npm_recon_commands: high {
  meta:
    description = "npm installer reconnaissance"
    confidence  = "0.66"

  strings:
$ = /\"uname -a/
    $ = "cat /etc/shadow"
  condition:
    package_scripts and any of them
}
