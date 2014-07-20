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

int webmount_getattr( const char *path ,
                    struct stat *stbuf )
{
    WEBMOUNT_DO_SIMPLE_REQUEST( WEBMOUNT_OPCODE_getattr )
    {
        struct attrs
        {
            uint32_t dev;
            uint32_t ino;
            uint32_t mode;
            uint32_t nlink;
            uint32_t uid;
            uint32_t gid;
            uint32_t rdev;
            uint32_t size;
            uint32_t atime;
            uint32_t mtime;
            uint32_t ctime;
            uint32_t blksize;
            uint32_t blocks;
        }
        attrs;

        WEBMOUNT_CHECK_RESPONSE_STATUS;
        if ( response.size != sizeof( struct attrs ) )
        {
            WEBMOUNT_CLEANUP;
            WEBMOUNT_RETURN( EBADMSG );
        }

        memset( stbuf , 0 , sizeof( struct stat ) );
        attrs = *( struct attrs * )response.payload;
        stbuf->st_dev = ntohl( attrs.dev );
        stbuf->st_ino = ntohl( attrs.ino );
        stbuf->st_mode = ntohl( attrs.mode );
        stbuf->st_nlink = ntohl( attrs.nlink );
        stbuf->st_uid = ntohl( attrs.uid );
        stbuf->st_gid = ntohl( attrs.gid );
        stbuf->st_rdev = ntohl( attrs.rdev );
        stbuf->st_size = ntohl( attrs.size );
        stbuf->st_atime = ntohl( attrs.atime );
        stbuf->st_mtime = ntohl( attrs.mtime );
        stbuf->st_ctime = ntohl( attrs.ctime );
        stbuf->st_blksize = ntohl( attrs.blksize );
        stbuf->st_blocks = ntohl( attrs.blocks );

        WEBMOUNT_CLEANUP;
        WEBMOUNT_RETURN( 0 );
    }
}
