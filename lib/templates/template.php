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

<?php

error_reporting( 0 );
if ( VERBOSE ) set_error_handler( 'store_error' );

/* UTILITY */

function store_error( $errno , $error )
{
    global $error_message;
    $error_message = $error;
}

function dump_ok()
{
    printf( '%c' , OK );
}

function dump_error( $error , $custom_error_message = null )
{
    global $error_message;
    printf( '%c' , $error );
    $message = $custom_error_message ? $custom_error_message : $error_message;
    if ( $message ) echo $message;
}

/* FUSE API */

function webmount_getattr( $data )
{
    $fields = unpack( 'a*path' , $data );

    $s = lstat( $fields[ 'path' ] );
    if ( $s )
    {
        dump_ok();
        echo pack( 'NNNNNNNNNNNNN' ,
                   $s[ 'dev' ] ,
                   $s[ 'ino' ] ,
                   $s[ 'mode' ] ,
                   $s[ 'nlink' ] ,
                   $s[ 'uid' ] ,
                   $s[ 'gid' ] ,
                   $s[ 'rdev' ] ,
                   $s[ 'size' ] ,
                   $s[ 'atime' ] ,
                   $s[ 'mtime' ] ,
                   $s[ 'ctime' ] ,
                   $s[ 'blksize' ] ,
                   $s[ 'blocks' ] );
    }
    else
    {
        dump_error( ENTRY_NOT_FOUND );
    }
}

function webmount_readdir( $data )
{
    $fields = unpack( 'a*path' , $data );

    $d = scandir( $fields[ 'path' ] );
    if ( $d )
    {
        dump_ok();
        foreach ( $d as $entry )
        {
            echo "$entry\x00";
        }
    }
    else
    {
        dump_error( CANNOT_ACCESS );
    }
}

function webmount_read( $data )
{
    $fields = unpack( 'Nsize/Noffset/a*path' , $data );

    $f = fopen( $fields[ 'path' ] , 'r' );
    if ( $f )
    {
        dump_ok();
        fseek( $f , $fields[ 'offset' ] );
        echo fread( $f , $fields[ 'size' ] );
        fclose( $f );
    }
    else
    {
        dump_error( CANNOT_ACCESS );
    }
}

function webmount_readlink( $data )
{
    $fields = unpack( 'a*path' , $data );

    $r = readlink( $fields[ 'path' ] );
    if ( $r )
    {
        dump_ok();
        echo $r;
    }
    else
    {
        dump_error( CANNOT_ACCESS );
    }
}

/*...*/

/* MAIN */

$post = file_get_contents( 'php://input' );
$opcode = ord( $post );
$function_name = $WEBMOUNT_OPCODE_NAMES[ $opcode ];
$data = substr( $post , 1 );
call_user_func( $function_name , $data );

?>
