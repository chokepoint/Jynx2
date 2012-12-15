#!/bin/sh
cat << NEXT > autokitter.sh
#!/bin/sh

mkdir jynx2
cd jynx2
cat << EOF > Makefile.b
NEXT

base64 Makefile >> autokitter.sh

cat << NEXT >> autokitter.sh
EOF
base64 -d Makefile.b > Makefile

cat << EOF > config.h.b
NEXT
base64 config.h >> autokitter.sh
cat << NEXT >> autokitter.sh
EOF
base64 -d config.h.b > config.h

echo "#define LIBC_PATH \"$(ldd $(which ls)|awk '/\tlibc\./ {print $3}')\"" >> config.h
echo "#endif" >> config.h

cat << EOF > jynx2.c.b
NEXT

base64 jynx2.c >> autokitter.sh
cat << NEXT >> autokitter.sh
EOF
base64 -d jynx2.c.b > jynx2.c

cat << EOF > reality.c.b
NEXT

base64 reality.c >> autokitter.sh
cat << NEXT >> autokitter.sh
EOF
base64 -d reality.c.b > reality.c

make
make install
cd ..
rm -rf jynx2
NEXT
