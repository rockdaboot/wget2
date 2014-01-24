# !/bin/sh -e

if test -z `which autoreconf`; then
  echo "No autoreconf found. You must install the autoconf package."
  exit 1
fi

mkdir m4 2>/dev/null

GTKDOCIZE=`which gtkdocize 2>/dev/null`
if test -z $GTKDOCIZE; then
  echo "No gtk-doc support found. You can't build the docs."
  echo "EXTRA_DIST =" >gtk-doc.make
  echo "CLEANFILES =" >>gtk-doc.make
else
  gtkdocize || exit $?
fi

autoreconf --install --force --symlink || exit $?

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
if test -z $GTKDOCIZE; then
  echo "./configure"
else
  echo "./configure --enable-gtk-doc"
fi
echo
