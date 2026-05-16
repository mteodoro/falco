backend example {
  .host = "127.0.0.1";
}

sub vcl_deliver {
  set req.http.X-Body-Bytes = req.body_bytes_read;
}

sub vcl_log {
  set req.http.X-Body-Bytes = req.body_bytes_read;
}
