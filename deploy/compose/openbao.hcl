ui = false
storage "file" {
  path = "/openbao/file"
}
listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/tls/cert.pem"
  tls_key_file    = "/tls/key.pem"
  tls_min_version = "tls13"
}
api_addr = "https://keys:8200"
