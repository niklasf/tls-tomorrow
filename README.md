tls-tomorrow
============

Try to make TLS connections with manipulated system time.

Useful to get early warnings for certificate expiration, even in complex
situations involving multiple possible chains of trust.

Will also detect if RSA certificates are expired, even when this would be
masked from a client with support for ECDSA.

Example
-------

```
$ cargo run -- --days 100 example.com
example.com with modern defaults in 100 days: invalid peer certificate contents: invalid peer certificate: CertExpired
example.com with tls12 rsa in 100 days: invalid peer certificate contents: invalid peer certificate: CertExpired
```
