#!/bin/bash

if [ -z "${CI_PROJECT_PATH}" ]; then
	CI_PROJECT_PATH=${PWD}
fi

function check_ret()
{
	ret=$1
	if [ "$ret" -ne 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		exit $ret
	fi

}

function exec_cmd()
{
	echo "executing $@"
	$@ >/dev/null 2>&1

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		exit 1
	fi
}

function exec_cmd_verbose()
{
	echo "executing $@"
	$@

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		exit 1
	fi
}

function install_wolfssl()
{
	CUR="${PWD}"

	echo "Installing wolfssl-4.8.1"
	cd /opt/dev/
	rm -rf wolfssl*

	wget -q https://github.com/wolfSSL/wolfssl/archive/refs/tags/v4.8.1-stable.tar.gz -O wolfssl.tgz
	tar xf wolfssl.tgz

	cd wolfssl-4.8.1-stable
	autoreconf -i -f
	exec_cmd ./configure --program-prefix="" --program-suffix="" --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --libexecdir=/usr/lib --sysconfdir=/etc --datadir=/usr/share --localstatedir=/var --mandir=/usr/man --infodir=/usr/info --disable-nls  --enable-reproducible-build --enable-lighty --enable-opensslall --enable-opensslextra --enable-sni --enable-stunnel --disable-crypttests --disable-examples --disable-jobserver --enable-ipv6 --enable-aesccm --enable-certgen --enable-chacha --enable-poly1305 --enable-dh --enable-arc4 --enable-tlsv10 --enable-tls13 --enable-session-ticket --disable-dtls --disable-curve25519 --disable-afalg --enable-devcrypto=no --enable-ocsp --enable-ocspstapling --enable-ocspstapling2 --enable-wpas --enable-fortress --enable-fastmath

	exec_cmd make
	exec_cmd make install

	cd ${CUR}
}

function generate_release()
{
	cd build
	cpack
	cd ..
}

function install_libusermngr()
{
	# clone and compile libusermngr
	rm -rf /opt/dev/usermngr
	exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/usermngr.git /opt/dev/usermngr

	echo "Compiling libusermngr"
	make clean -C /opt/dev/usermngr/src/
	make -C /opt/dev/usermngr/src/

	echo "installing libusermngr"
	cp -f /opt/dev/usermngr/src/libusermngr.so /usr/lib/bbfdm
}

function install_libbbf()
{
	COV_CFLAGS='-fprofile-arcs -ftest-coverage'
	COV_LDFLAGS='--coverage'
	VENDOR_LIST='iopsys'
	VENDOR_PREFIX='X_IOPSYS_EU_'

	echo "Compiling libbbf"
	if [ -d build ]; then
		rm -rf build
	fi

	mkdir -p build
	cd build
	cmake ../ -DCMAKE_C_FLAGS="$COV_CFLAGS " -DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS" -DBBFD_ENABLED=ON -DBBF_TR181=ON -DBBF_TR104=ON -DBBF_TR143=ON -DWITH_OPENSSL=ON -DBBF_JSON_PLUGIN=ON -DBBF_DOTSO_PLUGIN=ON -DBBF_VENDOR_EXTENSION=ON -DBBF_VENDOR_LIST="$VENDOR_LIST" -DBBF_VENDOR_PREFIX="$VENDOR_PREFIX" -DBBF_MAX_OBJECT_INSTANCES=255 -DCMAKE_INSTALL_PREFIX=/
	exec_cmd_verbose make

	echo "installing libbbf"
	exec_cmd_verbose make install
	ln -sf /usr/share/bbfdm/bbf.diag /usr/libexec/rpcd/bbf.diag
	cd ..

	echo "installing libusermngr"
	install_libusermngr
}

function install_libbbf_test()
{
	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	make clean -C test/bbf_test/
	make -C test/bbf_test/

	echo "installing libbbf_test"
	cp -f test/bbf_test/libbbf_test.so /usr/lib/bbfdm
}

function error_on_zero()
{
	ret=$1
	if [ "$ret" -eq 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		exit $ret
	fi

}

