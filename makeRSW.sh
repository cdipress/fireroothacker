#!/bin/sh

mkdir rsw-build
cd rsw-build

buildDir=$(pwd)

wget --prefer-family=IPv4 https://sourceforge.net/projects/levent/files/libevent/libevent-2.0/libevent-2.0.22-stable.tar.gz -O - | tar -zvxf -
wget --prefer-family=IPv4 https://dist.torproject.org/tor-0.2.5.10.tar.gz -O - | tar -zxvf -
wget --prefer-family=IPv4 https://www.openssl.org/source/openssl-0.9.8ze.tar.gz -O - | tar -zvxf -
wget --prefer-family=IPv4 http://zlib.net/zlib-1.2.8.tar.gz -O - | tar -zvxf -


mkdir -p opt


echo "###################" 
echo "Building libevent2" 
echo "###################" 
cd ${buildDir}/libevent-2.0.22-stable 
./configure --disable-shared --enable-static --with-pic --prefix ${buildDir}/opt\
            && make && make install

echo "###################" 
echo "Building zlib" 
echo "###################" 
cd ${buildDir}/zlib-1.2.8
CFLAGS="-fPIC" ./configure --static --prefix ${buildDir}/opt \
            && make && make install


echo "###################" 
echo "Building openssl" 
echo "###################" 
cd ${buildDir}/openssl-0.9.8ze
./config -fPIC no-shared zlib --prefix=${buildDir}/opt\
         && make && make install


echo "###################" 
echo "Building tor" 
echo "###################" 
cd ${buildDir}/tor-0.2.5.10

sed -i 's/extern const char tor_git_revision/const char tor_git_revision/' src/or/config.c

./configure --enable-static-libevent \
            --enable-static-openssl \
            --enable-static-zlib \
            --with-libevent-dir=${buildDir}/opt \
            --with-openssl-dir=${buildDir}/opt \
            --with-zlib-dir=${buildDir}/opt \
            --prefix=${buildDir}/opt\
            && make && make install

cp ${buildDir}/../rsw*.go .

go get code.google.com/p/rsc/qr
go get github.com/jcelliott/lumber

go build --ldflags '-extldflags "-static"' rsw-client.go rsw.go rsw-cc-client.go
go build rsw-cc.go rsw.go

cp rsw-cc ${buildDir}/..
cp rsw-client ${buildDir}/..

if [ "$?" -eq 0 ] ; then
   cd ${buildDir}/..
   rm -r ${buildDir}
fi

exit 0

