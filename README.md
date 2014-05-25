docker-mkimage-gentoo
=====================

A safe and flexible gentoo stage3 importer for docker, which:

 * ... supports 64-bit and x32-bit ABIs;

 * ... allows building from all different stage3 variants {nomultilib, hardened,
       hardened+nomultilib};

 * ... automatically uses latest Gentoo release, and tags the resulting docker
       image appropriately;

 * ... verifies archive digests to confirm that they are correctly signed by
       the Gentoo release key:

   > RSA key ID 2D182910

   > Key fingerprint = 13EB BDBE DE7A 1277 5DFD  B1BA BB57 2E0E 2D18 2910

   > "Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>"

 * ... confirms both SHA-512 and Whirlpool digests.

docker-mkimage.gentoo now requires that
[stdlib.sh](https://github.com/srcshelton/stdlib.sh/) is installed in
`/usr/local/lib`.  `curl` is used to download data, but `wget` will be used
automatically if `curl` is not present.  The only other requirements are GnuPG
`gpg` and OpenSSL.

Usage
-----

Show what actions would be performed:
```bash
docker-mkimage.gentoo --dry-run
```

Create an image from the current amd64 stage3 snapshot:
```bash
docker-mkimage.gentoo
```

Create an image from the current amd64 stage3 'nomultilib' snapshot:
```bash
docker-mkimage.gentoo nomultilib
```

Create an image from the current amd64 stage3 'hardened+nomultilib' snapshot:
```bash
docker-mkimage.gentoo hardened+nomultilib
```

Create an image from the current amd64 stage3 'nomultilib' snapshot, fetching
data from [mirror.ovh.net](http://mirror.ovh.net/gentoo-distfiles):
```bash
docker-mkimage.gentoo nomultilib http://mirror.ovh.net/gentoo-distfiles
```

Please note that the docker images cannot be used directly, but are intended to
form the base-image for Gentoo-based
[Dockerfile](http://docs.docker.io/reference/builder/)s
