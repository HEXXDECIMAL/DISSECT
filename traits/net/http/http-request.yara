// Migrated from malcontent: net/http/http-request.yara

rule http_request: low {
  meta:
    description = "makes HTTP requests"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$httpRequest   = "httpRequest"
    $user_agent    = "User-Agent"
    $assemble      = "httpAssemble"
    $connect       = "httpConnect"
    $close         = "httpClose"
    $http1         = "HTTP/1."
    $http2         = "Referer" fullword
    $uri           = "open-uri" fullword
    $http_get      = "http.get" fullword
    $http_connect  = "HTTPConnection" fullword
    $https_connect = "HTTPSConnection" fullword
    $axios         = "axios" fullword
    $ruby_http_get = "HTTP.get" fullword
    $java_get      = "HttpURLConnection"
  condition:
    any of them
}
