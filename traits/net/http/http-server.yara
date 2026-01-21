// Migrated from malcontent: net/http/http-server.yara

rule http_server: medium {
  meta:
    description = "serves HTTP requests"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    pledge      = "inet"

  strings:
$gin         = "gin-gonic/"
    $gin_handler = "gin.HandlerFunc"
    $listen      = "httpListen"
    $http_listen = "http.Listen"
    $http_server = "http.server"
  condition:
    filesize < 10MB and any of them
}
