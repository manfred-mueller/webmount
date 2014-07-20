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

int webmount_readdir( const char *path ,
                    void *buf ,
                    fuse_fill_dir_t filler ,
                    off_t offset ,
                    struct fuse_file_info *fi )
{
    WEBMOUNT_DO_SIMPLE_REQUEST( WEBMOUNT_OPCODE_readdir )
    {
        char *p;

        WEBMOUNT_CHECK_RESPONSE_STATUS;

        for ( p = response.payload ;
              p - response.payload < response.size ;
              p += strnlen( p , response.size - ( p - response.payload ) ) + 1 )
        {
            filler( buf , p , NULL , 0 );
        }

        WEBMOUNT_CLEANUP;
        WEBMOUNT_RETURN( 0 );
    }
}
