/* This file is part of webmount.

 webmount is a fork from httpfs, Copyright (c) 2013 Andrea Cardaci, Emilio Pinna
 Copyright (c) 2013 Manfred Mueller <manfred.mueller@fluxflux.net>

 Security related functions, especially the ability to create, modify or delete
 nodes, files and folders and to break out of the chroot have been stripped off.
 Name and location of the server folder to be used as chroot has been hardcoded.

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef _WEBMOUNT_DEBUG_H
#define _WEBMOUNT_DEBUG_H

#include <stdio.h>
#include "net.h"

#define DEBUG_PREFIX ">>> "

#define LOG( string ) \
    do if ( WEBMOUNT_VERBOSE ) fprintf( stderr , DEBUG_PREFIX "%s\n" , string ); \
    while ( 0 )

#define LOGF( format , ... ) \
    do if ( WEBMOUNT_VERBOSE ) fprintf( stderr , DEBUG_PREFIX format "\n" , ##__VA_ARGS__ ); \
    while ( 0 )

#define DUMP_RAW_DATA( label , raw_data ) \
    do if ( WEBMOUNT_VERBOSE ) { \
            fprintf( stderr , DEBUG_PREFIX "%s%zu byte: " , \
                     label , raw_data.size ); \
            webmount_dump_raw_data( &raw_data ); } \
    while ( 0 )

extern int WEBMOUNT_VERBOSE;

void webmount_dump_raw_data( struct raw_data *raw_data );

#endif
