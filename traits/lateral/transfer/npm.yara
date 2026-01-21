// Migrated from malcontent: c2/tool_transfer/npm.yara

rule npm_dropper: critical {
  meta:
    description = "NPM binary dropper"
    mbc         = "OB0013"
    attack      = "T1021"
    confidence  = "0.66"
    ref         = "https://www.reversinglabs.com/blog/a-lurking-npm-package-makes-the-case-for-open-source-health-checks"
    filetypes   = "js,ts"

  strings:
$npm_format      = /"format":/
    $npm_lint        = /"lint":/
    $npm_postversion = /"postversion":/
    $npm_postinstall = /"postinstall":/
    $fetch           = /"(curl|wget) /
    $url             = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $chmod           = "chmod"
  condition:
    filesize < 16384 and 2 of ($npm*) and $fetch and $url and $chmod
}
