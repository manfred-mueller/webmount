# This file is part of webmount.
#
# webmount is a fork from httpfs, Copyright (c) 2013 Andrea Cardaci, Emilio Pinna
# Copyright (c) 2013 Manfred Mueller <manfred.mueller@fluxflux.net>
#
# Security related functions, especially the ability to create, modify or delete
# nodes, files and folders and to break out of the chroot have been stripped off.
# Name and location of the server folder to be used as chroot has been hardcoded.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

release debug: build

release: BUILD_DIR=./build-release/
release: BUILD_TYPE=Release

debug: BUILD_DIR=./build-debug/
debug: BUILD_TYPE=Debug

build:
	rm -fr $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake -DCMAKE_INSTALL_PREFIX=/usr -DLOCALE_INSTALL_DIR=/usr/share/locale -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) .. && make

install:
	cd ./build-release/ && make install

uninstall:
	cd ./build-release/ && xargs rm < install_manifest.txt

clean:
	rm -fr ./build-release/ ./build-debug/

.PHONY: build build-release build-debug install uninstall clean
