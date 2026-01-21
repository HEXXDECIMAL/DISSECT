// Migrated from malcontent: discover/ip/geoip.yara

rule geoip_website_value: high {
  meta:
    description = "public service for IP geolocation"
    confidence  = "0.66"

  strings:
$p_ipify     = "ip-api.com"
    $p_wtfismyip = "freegeoip"
    $p_geo       = "geolocation-db.com"

    $not_pypi_index = "testpack-id-lb001"
  condition:
    any of ($p*) and none of ($not*)
}
