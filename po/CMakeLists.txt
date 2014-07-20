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

###############################################################################
# WE NEED GETTEXT
##############################################################################
MESSAGE ( STATUS "<Locating Gettext>" )
FIND_PACKAGE ( Gettext REQUIRED )
INCLUDE_DIRECTORIES ( ${GETTEXT_INCLUDE_DIR} )
FILE ( GLOB _po_files *.po )
SET ( _gmoFiles )
###############################################################################
# WE NEED -DLOCALE_INSTALL_DIR
##############################################################################
IF (NOT LOCALE_INSTALL_DIR)
        MESSAGE("NOTE: Use -DLOCALE_INSTALL_DIR=/some/path to define your locale
                install directory. Locales will not be installed")
ELSE(NOT LOCALE_INSTALL_DIR)
###############################################################################
# CREATE .MO FOR EACH .PO
###############################################################################
FOREACH ( _current_PO_FILE ${_po_files} )
GET_FILENAME_COMPONENT( _lang ${_current_PO_FILE} NAME_WE )
SET( _gmoFile ${CMAKE_BINARY_DIR}/po/${_lang}.mo )
add_custom_command( OUTPUT ${_gmoFile}
COMMAND ${GETTEXT_MSGFMT_EXECUTABLE} -o ${_gmoFile} ${_current_PO_FILE}
WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
DEPENDS ${_current_PO_FILE}
)
INSTALL ( FILES ${CMAKE_BINARY_DIR}/po/${_lang}.mo
DESTINATION ${LOCALE_INSTALL_DIR}/${_lang}/LC_MESSAGES/ RENAME webmount.mo )
LIST(APPEND _gmoFiles ${_gmoFile})
ENDFOREACH(_current_PO_FILE)
ADD_CUSTOM_TARGET(pofiles ALL DEPENDS ${_gmoFiles})
###############################################################################
ENDIF(NOT LOCALE_INSTALL_DIR)
