These are independently generated local TLS test fixtures, not service data.
`server.der` is a self-signed leaf certificate for `fixed.test`, valid for ten
years from November 2026. `server-key.der` is its deliberately public test-only
PKCS#8 private key. Do not use either in a deployment. Tests add this certificate
to a private in-memory trust store; the application continues to use WebPKI roots.
