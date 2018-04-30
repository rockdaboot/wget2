./configure
make -j$(nproc)
make -j$(nproc) check
