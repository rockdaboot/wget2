# !/bin/sh -e

gtkdocize
autoreconf --install --force --symlink

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure --enable-gtk-doc"
echo
