# Building Wget2 with Docker

This guide explains how to build static binaries of Wget2 using Docker, how caching works, and how to use incremental compilation during development.

---

## 1. Quick Start

### Build static Windows binary (`wget2.exe`)

From the root of the repository, run:

```bash
# 1. Build the image (takes ~7 minutes using prebuilt dependencies)
docker build -t wget2/win32/static -f contrib/Dockerfile.win32.static .

# 2. Extract wget2.exe to current directory (works in any shell on any OS)
docker create --name temp-wget2 wget2/win32/static
docker cp temp-wget2:/usr/local/wget2/src/wget2.exe .
docker rm -f temp-wget2
```

### Build static Linux binary (`wget2`)

```bash
# 1. Build the static musl image
docker build -t wget2/static/amd64 -f contrib/Dockerfile.musl.static.amd64 .

# 2. Extract wget2 to current directory (works in any shell on any OS)
docker create --name temp-wget2 wget2/static/amd64
docker cp temp-wget2:/usr/local/wget2/src/wget2 .
docker rm -f temp-wget2
```

---

## 2. Build Modes for Windows (`BUILD_MODE`)

The Windows Dockerfile ([contrib/Dockerfile.win32.static](../../contrib/Dockerfile.win32.static)) supports two build modes:

### `fast` (Default — Recommended)

```bash
docker build -t wget2/win32/static -f contrib/Dockerfile.win32.static .
```

* **Build time:** ~5 to 7 minutes on a clean run (under 2 minutes once the base image is downloaded).
* **How it works:** It uses the official GNU Wget2 CI base image (`registry.gitlab.com/gnuwget/build-images:buildenv-wget2-mingw-static`), maintained upstream by the Wget team on GitLab. All 12 external static libraries (`gnutls`, `nettle`, `gmp`, `libiconv`, `pcre2`, `libpsl`, etc.) are already compiled and ready to use.

### `full` (From Scratch)

```bash
docker build --build-arg BUILD_MODE=full -t wget2/win32/static -f contrib/Dockerfile.win32.static .
```

* **Build time:** ~45 to 60 minutes.
* **How it works:** Compiles Debian toolchains and all 12 external dependencies from source.
* **When to use:** Use this mode if you need a completely offline build, if you cannot access `registry.gitlab.com`, or if you need an audited build from upstream source tarballs.

---

## 3. How Rebuild Caching Works (`ccache` + BuildKit)

When developing code, running `docker build` normally invalidates Docker's layer cache as soon as any `.c` or `.h` file is modified.

To prevent having to recompile the 120+ GNU Gnulib modules and all of Wget2 from scratch every time, the Dockerfiles use:

1. **Docker BuildKit Persistent Cache Mounts:**
   The `make` step uses `--mount=type=cache,target=/root/.cache/ccache`. This keeps compiler cache files on your host machine across builds, outside of Docker's layer system.
2. **`ccache` compiler caching:**
   `ccache` intercepts compiler calls. When you edit a single file in `src/`, `ccache` reuses compiled `.o` files for all unchanged files (including all of Gnulib and libwget).
3. **Rebuild time:**
   Rebuilds drop from ~4 minutes down to **under 20 seconds**.

---

## 4. Interactive Development Workflow (Fastest Inner Loop)

If you are actively modifying code in `src/` or `libwget/`, rebuilding a Docker container on every change is still slower than native compilation.

The fastest workflow is to mount your local repository into an interactive container once:

### 1. Start the development container with your folder mounted

```bash
# Build the builder image once
docker build -t wget2-dev -f contrib/Dockerfile.win32.static .

# Run an interactive shell with your code mounted at /wget2
docker run --rm -it -v .:/wget2 -w /wget2 wget2-dev bash
```

### 2. Configure once inside the container

```bash
./bootstrap --skip-po
./configure --build=x86_64-pc-linux-gnu --host=x86_64-w64-mingw32 --disable-shared --enable-static --without-gpgme --enable-threads=windows
make -C lib -j$(nproc)
```

### 3. Edit code on your host machine and recompile in 1 second

Whenever you edit a `.c` file in your editor on your host machine, simply switch to the container terminal and type:

```bash
make -C src -j$(nproc)
```

GNU Make checks the timestamps and recompiles **only the files you changed**. The new `src/wget2.exe` is relinked in **1 to 2 seconds**.
