tls-tomorrow
============

Try to make TLS connections with manipulated system time.

Useful to get early warnings for certificate expiration, even in complex
situations involving multiple possible chains of trust.

Example
-------

```
$ cargo run -- --days 100 example.com
example.com in 100 days: invalid certificate: CertExpired
```
