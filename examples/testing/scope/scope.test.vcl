// @scope: deliver
// @suite: req.body_bytes_read in vcl_deliver
sub test_deliver_body_bytes_read {
  testing.call_subroutine("vcl_deliver");
  assert.equal(req.http.X-Body-Bytes, "0");
}

// @scope: log
// @suite: req.body_bytes_read in vcl_log
sub test_log_body_bytes_read {
  testing.call_subroutine("vcl_log");
  assert.equal(req.http.X-Body-Bytes, "0");
}
