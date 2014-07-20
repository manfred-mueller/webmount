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

project( webmount )

# CMake setup
cmake_minimum_required( VERSION 2.8 )
find_package( PkgConfig )


# Versioning
SET(VERSION_MAJOR 0)
SET(VERSION_MINOR 2)
SET(VERSION ${VERSION_MAJOR}.${VERSION_MINOR})

# sources
file( GLOB fuse_api lib/fuse_api/*.c )
file( GLOB lib_src lib/*.c )
file( GLOB templates RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/lib/templates/ lib/templates/* )

# process templates
set( templates_h "" )
foreach( template ${templates} )
set( template_h ${template}.h )
list( APPEND templates_h ${template_h} )
add_custom_command(
  OUTPUT ${template_h}
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/lib/templates/${template} ${template}
  COMMAND xxd -i ${template} ${template_h}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/lib/templates/${template}
)
endforeach( template )
include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

# external libraries
find_package( CURL )
pkg_check_modules( FUSE REQUIRED fuse )
add_definitions( ${FUSE_CFLAGS} -DFUSE_USE_VERSION=29 )

# webmount library
add_library( webmount STATIC ${lib_src} ${fuse_api} ${templates_h} )

# compilation
include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/lib/ )
add_executable( webmount-bin src/main.c )
set_target_properties( webmount-bin PROPERTIES OUTPUT_NAME webmount)
add_definitions( -Wall )
target_link_libraries( webmount-bin webmount ${CURL_LIBRARY} ${FUSE_LIBRARIES} )
add_subdirectory(po)

install( PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/webmount DESTINATION bin )
install( FILES README DESTINATION doc/webmount-${VERSION} )
install( FILES ChangeLog DESTINATION doc/webmount-${VERSION} )
install( FILES License DESTINATION doc/webmount-${VERSION} )
