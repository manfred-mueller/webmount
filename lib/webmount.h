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

#ifndef _WEBMOUNT_WEBMOUNT_H
#define _WEBMOUNT_WEBMOUNT_H

/*

  Request format:

  +--------+--------+------+------+
  | opcode | fields | path | data |
  +--------+--------+------+------+

  - opcode: 1 byte that identifies the requested operation (see "operation code"
            enum)

  - fields: arbitrarily long (even 0) packed data in big endian byte order

  - path: absolute Unix-like path ('\0' terminated string)

  - data: arbitrarily long (even 0) raw data

  Response format:

  +--------+------+
  | status | data |
  +--------+------+

  - status: 1 byte that describes the result of the operation (see "response
            status" enum)

  - data: arbitrarily long (even 0) raw data

  NOTE: these messages are carried over HTTP so there's no need to include an
        additional length field

*/

/* common includes for API implementation */
#include <fuse.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include "debug.h"
#include "net.h"

/* convenience macros used to implement the FUSE API functions; 'response' is
   the data received and it's available to the implementation; a structure named
   'header' may be filled with values to be passed to the PHP script before
   calling this macros; a 'struct raw_data raw_data' may contains the additional
   data to pass to the PHP script; this macros expect a following block where
   the logic should be implemented */
#define WEBMOUNT_DO_SIMPLE_REQUEST( op ) \
    _WEBMOUNT_DO_REQUEST( op , fuse_get_context()->private_data , \
    webmount_prepare_request( fuse_get_context()->private_data , \
                            &_in , op , NULL , path , NULL ); )

#define WEBMOUNT_DO_REQUEST_WITH_HEADER( op ) \
    _WEBMOUNT_DO_REQUEST( op , fuse_get_context()->private_data , \
    _header_data.payload = ( char * )&header; \
    _header_data.size = sizeof( header ); \
    webmount_prepare_request( fuse_get_context()->private_data , \
                            &_in , op , &_header_data , path , NULL ); )

#define WEBMOUNT_DO_REQUEST_WITH_DATA( op ) \
    _WEBMOUNT_DO_REQUEST( op , fuse_get_context()->private_data , \
    webmount_prepare_request( fuse_get_context()->private_data , \
                            &_in , op , NULL , path , &raw_data ); )

#define WEBMOUNT_DO_REQUEST_WITH_HEADER_AND_DATA( op ) \
    _WEBMOUNT_DO_REQUEST( op , fuse_get_context()->private_data , \
    _header_data.payload = ( char * )&header; \
    _header_data.size = sizeof( header ); \
    webmount_prepare_request( fuse_get_context()->private_data , \
                            &_in , op , &_header_data , path , &raw_data ); )

/* common */
#define _WEBMOUNT_DO_REQUEST( op , webmount , prepare_header ) \
    LOGF( "REQUEST: %s (%i)" , \
          WEBMOUNT_OPCODE_NAMES[ op ] , op ); \
    struct raw_data _in = { 0 } , _out = { 0 } , _header_data = { 0 }; \
    struct raw_data response = { 0 }; \
    ( void )response; \
    ( void )_header_data; \
    prepare_header \
    DUMP_RAW_DATA( "SENDING " , _in ); \
    if ( CURLE_OK != webmount_do_post( webmount , &_in , &_out ) ) { \
        LOG( "REQUEST: failed" ); \
        WEBMOUNT_CLEANUP; \
        return -ECOMM; \
    } else

/* return errno from FUSE callback functions */
#define WEBMOUNT_RETURN( errno ) \
    LOGF( "RETURN: %s (%i)" , strerror( errno ) , errno );  \
    return -errno;

/* check the response status and return if an error is occurred */
#define WEBMOUNT_CHECK_RESPONSE_STATUS \
    response.payload = _out.payload + 1; \
    response.size = _out.size - 1; \
    DUMP_RAW_DATA( "RECEIVED " , _out ); \
    switch ( *_out.payload ) { \
    _WEBMOUNT_CHECK_HANDLE_ERROR( ENTRY_NOT_FOUND , ENOENT ) \
    _WEBMOUNT_CHECK_HANDLE_ERROR( CANNOT_ACCESS , EACCES ) \
    _WEBMOUNT_CHECK_HANDLE_ERROR( NOT_PERMITTED , EPERM ) \
    case WEBMOUNT_STATUS_OK: _WEBMOUNT_DUMP_STATUS; break; \
    default: WEBMOUNT_CLEANUP; WEBMOUNT_RETURN( EBADMSG ); \
    }

#define _WEBMOUNT_CHECK_HANDLE_ERROR( status , errno ) \
    case WEBMOUNT_STATUS_##status: \
    _WEBMOUNT_DUMP_STATUS; WEBMOUNT_CLEANUP; \
    WEBMOUNT_RETURN( errno )

#define _WEBMOUNT_DUMP_STATUS \
    LOGF( "RESPONSE: %s (%i)" , \
          WEBMOUNT_STATUS_NAMES[ ( int )*_out.payload ] , *_out.payload ); \

/* to be called before return in FUSE API functions */
#define WEBMOUNT_CLEANUP \
    free( _in.payload ); \
    free( _out.payload )

/* initialization errors */
enum
{
    WEBMOUNT_NO_ERROR ,
    WEBMOUNT_FUSE_ERROR ,
    WEBMOUNT_CURL_ERROR ,
    WEBMOUNT_UNREACHABLE_SERVER_ERROR ,
    WEBMOUNT_WRONG_CHROOT_ERROR ,
    WEBMOUNT_ERRNO_ERROR
};

/* context */
struct webmount
{
    const char *url;
    const char *remote_chroot;
    CURL *curl;
};

/* operation codes */
#define _( x ) WEBMOUNT_OPCODE_##x ,
enum { WEBMOUNT_OPCODE_NONE ,
#include "fuse_functions.def"
};
extern const char *WEBMOUNT_OPCODE_NAMES[];

/* response status */
#define _( x ) WEBMOUNT_STATUS_##x ,
enum {
#include "statuses.def"
};
extern const char *WEBMOUNT_STATUS_NAMES[];

int webmount_fuse_start( struct webmount *webmount ,
                       const char *url ,
                       const char *remote_chroot ,
                       char *mount_point );

void webmount_prepare_request( struct webmount *webmount ,
                             struct raw_data *in ,
                             uint8_t opcode ,
                             struct raw_data *header ,
                             const char *path ,
                             struct raw_data *data );

#endif
