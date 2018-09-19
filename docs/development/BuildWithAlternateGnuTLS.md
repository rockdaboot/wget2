To implement and test "TLS False Start", I cloned GnuTLS into /home/tim/src/gnutls and built the 'master' branch, which is post-3.5.2. My system GnuTLS just has 3.4.x which does not support this new experimental feature.

Now cd into wget2 source code directory and simply
```
$ GNUTLS_CFLAGS="-I/home/tim/src/gnutls/lib/includes" GNUTLS_LIBS=-L/home/tim/src/gnutls/lib ./configure && make
...
$ $ ldd src/wget2_noinstall|grep gnutls
        libgnutls.so.30 => /usr/oms/src/gnutls/lib/.libs/libgnutls.so.30 (0x00007f627cc35000)
```

You have to use absolute paths, tilde expansion does not work out.

This procedure should work out with all libs supported by pkg-config, see
```
$ ./configure --help
```
