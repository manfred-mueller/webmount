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

#ifndef _WEBMOUNT_FUSE_API_H
#define _WEBMOUNT_FUSE_API_H

int webmount_getattr( const char * , struct stat * );
int webmount_readlink( const char * , char * , size_t );
int webmount_utime( const char * , struct utimbuf * );
int webmount_open( const char * , struct fuse_file_info * );
int webmount_read( const char * , char * , size_t , off_t , struct fuse_file_info * );
int webmount_statfs( const char * , struct statvfs * );
int webmount_flush( const char * , struct fuse_file_info * );
int webmount_release( const char * , struct fuse_file_info * );
int webmount_fsync( const char * , int , struct fuse_file_info * );
int webmount_getxattr( const char * , const char * , char * , size_t );
int webmount_listxattr( const char * , char * , size_t );
int webmount_opendir( const char * , struct fuse_file_info * );
int webmount_readdir( const char * , void * , fuse_fill_dir_t , off_t , struct fuse_file_info * );
int webmount_releasedir( const char * , struct fuse_file_info * );
int webmount_fsyncdir( const char * , int , struct fuse_file_info * );
int webmount_access( const char * , int );
int webmount_fgetattr( const char * , struct stat * , struct fuse_file_info * );
int webmount_utimens( const char * , const struct timespec [2] );
int webmount_bmap( const char * , size_t , uint64_t * );
int webmount_ioctl( const char * , int , void * , struct fuse_file_info * , unsigned int , void * );
int webmount_poll( const char * , struct fuse_file_info * , struct fuse_pollhandle * , unsigned * );

#endif
