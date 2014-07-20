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

#include "webmount.h"
#include "fuse_api/fuse_api.h"

const char *WEBMOUNT_OPCODE_NAMES[] = {
    "NONE" ,
#define _( x ) #x ,
#include "fuse_functions.def"
    NULL
};

const char *WEBMOUNT_STATUS_NAMES[] = {
#define _( x ) #x ,
#include "statuses.def"
    NULL
};

static int check_remote_availability( struct webmount *webmount )
{
    _WEBMOUNT_DO_REQUEST( WEBMOUNT_OPCODE_getattr , webmount ,
                        webmount_prepare_request( webmount , &_in , WEBMOUNT_OPCODE_getattr ,
                                                NULL , "/" , NULL ); )
    {
        WEBMOUNT_CHECK_RESPONSE_STATUS;
        WEBMOUNT_CLEANUP;
        WEBMOUNT_RETURN( 0 );
    }
}

int webmount_fuse_start( struct webmount *webmount ,
                       const char *url ,
                       const char *remote_chroot ,
                       char *mount_point )
{
    int argc;
    char *argv[ 4 ];
    int rv;

    const struct fuse_operations operations = {
#define _( x ) .x = webmount_##x ,
#include "fuse_functions.def"
    };

    webmount->url = url;
    webmount->remote_chroot = remote_chroot;

    /* initialize curl */
    webmount->curl = curl_easy_init();
    if ( !webmount->curl )
    {
        return WEBMOUNT_CURL_ERROR;
    }

    /* check remote availability before mounting */
    rv = -check_remote_availability( webmount );
    switch ( rv )
    {
    case 0: break;
    case ECOMM: return WEBMOUNT_UNREACHABLE_SERVER_ERROR;
    case ENOENT: return WEBMOUNT_WRONG_CHROOT_ERROR;
    default:
        {
            errno = rv;
            return WEBMOUNT_ERRNO_ERROR;
        }
    }

    /* fuse arguments */
    argc = 0;
    argv[ argc++ ] = "webmount";
    argv[ argc++ ] = "-s"; /* single thread */
    if ( WEBMOUNT_VERBOSE ) argv[ argc++ ] = "-d"; /* debug and core dump */
    argv[ argc++ ] = mount_point;

    /* start loop */
    if ( fuse_main( argc , argv , &operations , webmount ) )
    {
        return WEBMOUNT_FUSE_ERROR;
    }

    return WEBMOUNT_NO_ERROR;
}

void webmount_prepare_request( struct webmount *webmount ,
                             struct raw_data *in ,
                             uint8_t opcode ,
                             struct raw_data *header ,
                             const char *path ,
                             struct raw_data *data )
{
    size_t offset , header_size , remote_chroot_length , path_length , data_size;

    header_size = ( header ? header->size : 0 );
    remote_chroot_length = ( webmount->remote_chroot ? strlen( webmount->remote_chroot ) : 0 );
    path_length = strlen( path ) + 1;
    data_size = ( data ? data->size : 0 );

    in->size = 1 + header_size + remote_chroot_length + path_length + data_size;
    in->payload = malloc( in->size );

    /* opcode */
    *in->payload = opcode;

    /* header */
    offset = 1;
    if ( header )
    {
        memcpy( in->payload + offset , header->payload , header->size );
    }

    /* path */
    offset += header_size;
    memcpy( in->payload + offset , webmount->remote_chroot , remote_chroot_length );
    offset += remote_chroot_length;
    memcpy( in->payload + offset , path , path_length );

    /* data */
    if ( data )
    {
        offset += path_length;
        memcpy( in->payload + offset , data->payload , data->size );
    }
}
