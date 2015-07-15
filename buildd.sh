#!/bin/bash

if [ -d build ]; then
	echo "Deleting build directory"
	rm -rf build || true
fi

mkdir build
cd build

echo "Cmake source"
cmake -G"Eclipse CDT4 - Unix Makefiles" -D_ECLIPSE_VERSION=4.5 -D CMAKE_BUILD_TYPE=Debug ../project

mv .project ..
mv .cproject ..
echo "Make"
make -j 4 
echo "Test"
ctest --output-on-failure .
