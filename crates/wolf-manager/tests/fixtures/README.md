The PEM certificate and key are disposable localhost TLS fixtures generated for
native HTTPS integration tests. They grant no deployment identity or access to
any external system. Production configuration always requires mounted operator
certificates and protected private keys; these fixture paths are never defaults.
