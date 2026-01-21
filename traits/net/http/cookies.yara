// Migrated from malcontent: net/http/cookies.yara

rule http_cookie: medium {
  meta:
    description = "access HTTP resources using cookies"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"
    ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"

  strings:
$Cookie       = "Cookie"
    $HTTP         = "HTTP"
    $http_cookie  = "http_cookie"
    $http_cookie2 = "HTTP_COOKIE"
  condition:
    any of ($http_cookie*) or ($Cookie and $HTTP)
}
