rule ruby_http_dropper {
    meta:
        description = "Ruby script that downloads and executes payload"
        capability = "c2/dropper/http"
        criticality = "HOSTILE"
        confidence = 95

    strings:
        $http_get = /Net::HTTP\.(get|get_response)/ nocase
        $file_write = /File\.open\([^)]*['"]w/ nocase
        $chmod = /\.chmod\s*\(/ nocase
        $system = /system\s*\(/ nocase
        $tmp = "/tmp/" nocase

    condition:
        all of them
}

rule ruby_base64_obfuscated_c2 {
    meta:
        description = "Ruby script with Base64-encoded C2 domain"
        capability = "c2/channels/dns-obfuscated"
        criticality = "HOSTILE"
        confidence = 90

    strings:
        $base64_decode = "Base64.decode64" nocase
        $resolv = "Resolv.getaddress" nocase
        $http = "Net::HTTP" nocase
        $base64_pattern = /[A-Za-z0-9+\/]{20,}={0,2}/ // Long base64 string

    condition:
        all of them
}

rule ruby_chmod_777_executable {
    meta:
        description = "Makes file world-executable (chmod 0777)"
        capability = "fs/permission-modify/world-executable"
        criticality = "HOSTILE"
        confidence = 95

    strings:
        $chmod_777 = /\.chmod\s*\(\s*0[o]?777\s*\)/ nocase
        $chmod_oct = /chmod\s+0777/ nocase

    condition:
        any of them
}

rule ruby_malware_dropper_full_chain {
    meta:
        description = "Complete Ruby malware dropper chain: DNS -> HTTP -> Write -> Chmod -> Execute"
        capability = "c2/dropper/full-chain"
        criticality = "HOSTILE"
        confidence = 98

    strings:
        $resolv = "Resolv" nocase
        $base64 = "Base64.decode64" nocase
        $http = "Net::HTTP" nocase
        $file_write = "File.open" nocase
        $binmode = ".binmode" nocase
        $chmod = ".chmod" nocase
        $system = "system(" nocase
        $tmp = "/tmp/" nocase

    condition:
        6 of them
}

rule ruby_dropper_tmp_execution {
    meta:
        description = "Write to /tmp, make executable, and execute"
        capability = "c2/dropper/tmp-exec"
        criticality = "HOSTILE"
        confidence = 95

    strings:
        $tmp_write = /File\.open\s*\(\s*['"]\s*\/tmp\// nocase
        $chmod = /\.chmod\s*\(/ nocase
        $system_tmp = /system\s*\(\s*['"]\s*\/tmp\// nocase

    condition:
        all of them
}

rule ruby_reverse_dns_c2 {
    meta:
        description = "Uses DNS resolution to hide C2 domain"
        capability = "c2/channels/dns-lookup"
        criticality = "HOSTILE"
        confidence = 85

    strings:
        $resolv_getaddress = "Resolv.getaddress" nocase
        $http = /Net::HTTP/ nocase
        $base64 = "Base64" nocase

    condition:
        all of them
}

rule ruby_binary_file_write {
    meta:
        description = "Write binary file (potential payload)"
        capability = "fs/write-binary"
        criticality = "NOTABLE"
        confidence = 80

    strings:
        $binmode = ".binmode" nocase
        $write = ".write(" nocase
        $wb_mode = /'wb[+]?'/ nocase
        $wb_mode2 = /"wb[+]?"/ nocase

    condition:
        $binmode or ($write and ($wb_mode or $wb_mode2))
}

rule ruby_http_body_write_pattern {
    meta:
        description = "Write HTTP response body to file (dropper pattern)"
        capability = "c2/dropper/http-body-write"
        criticality = "HOSTILE"
        confidence = 90

    strings:
        $http_response = /\.get_response/ nocase
        $body = /\.body/ nocase
        $file_write = /File\.open/ nocase
        $write = /\.write\s*\(/ nocase

    condition:
        all of them
}
