// Migrated from malcontent: net/http/websocket.yara

rule websocket: medium {
  meta:
    description = "supports web sockets"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    ref         = "https://www.rfc-editor.org/rfc/rfc6455"

  strings:
$ref  = /[a-zA-Z]{0,16}[wW]ebSocket[\w:]{0,32}/ fullword
    $ref2 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $ref3 = "wss://"
    $ref4 = "from websocket"
  condition:
    any of them
}

rule websocket_send_json: medium {
  meta:
    description = "uploads JSON data via web socket"
    mbc         = "C0002"
    attack      = "T1071.001"
    confidence  = "0.66"
    filetypes   = "js,ts"

  strings:
$send = "ws.send(JSON.stringify("
  condition:
    websocket and $send
}
