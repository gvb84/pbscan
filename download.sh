#!/bin/sh

ORIGPATH=$PWD
NM="netmap"
LU="libuinet"

if [ ! -d $NM ]; then
	git clone https://github.com/fichtner/netmap
	cd $NM
	git checkout 32e06f9d18bf82e40a7c5b6e769c0ca7607913fc
	cd $ORIGPATH
fi

if [ ! -d $LU ]; then
	git clone https://github.com/pkelsey/libuinet.git
	cd $LU
	git checkout 0db87ba4a5b2113eb7cf529a3aa7170431a3bf4d
	cd $ORIGPATH
fi
