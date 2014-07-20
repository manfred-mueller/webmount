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

#include <stdlib.h>
#include "generators.h"
#include "webmount.h"
#include "fuse_api/fuse_api.h"
#include "version.h"
#include <libintl.h>
#include <locale.h>

#define _(Text) gettext(Text)

static void usage()
{
    fprintf( stderr ,
             _("\nUsage:\n\n"
             "      webmount -h,--help\n"
             "      webmount -l,--license\n"
             "      webmount -v,--version\n"
             "      webmount generate php > <php_file>\n"
             "      webmount mount <url> <mount_point>\n\n"));
}

static void help()
{
    fprintf( stderr , _("\nwebmount " WEBMOUNT_VERSION "\n\n"
    "Sample usage\n"
    "------------\n"
    "\n"
    "1. Generate a PHP script:\n"
    "\n"
    "        webmount generate php > webmount.php\n"
    "\n"
    "2. Place the generated script in an accessible location inside the document\n"
    "   root of your web server and create a /webmount folder in the servers real root.\n"
    "   To be on the safe side, adjust the folder's permissions to be read only.\n"
    "   You can even mount an iso file as loop, as long as it is mounted at /webmount/.\n"
    "\n"
    "3. Mount the remote filesystem:\n"
    "\n"
    "        mkdir /tmp/webmount/\n"
    "        webmount mount http://target.com/webmount.php /tmp/webmount\n"
    "\n"
    "4. Now the remote `/webmount/` is mounted in `/tmp/webmount/`, head there to\n"
    "   browse the remote files.\n"
    "\n"
    "5. Unmount the filesystem:\n"
    "\n"
    "        fusermount -u /tmp/webmount/\n"
    "\n"
    "Prepare the environment\n"
    "-----------------------\n"
    "\n"
    "Make sure the current user is in the `fuse` group, this preliminary step is\n"
    "mandatory to use any FUSE filesystem. You can list the groups you belong to with\n"
    "`groups`, if that includes `fuse` you're done, otherwise:\n"
    "\n"
    "    sudo adduser john fuse\n"
    "\n"
    "Then log out and back in or start a new shell with:\n"
    "\n"
    "newgrp fuse\n"
    "\n"
    "to inform the system about the changes.\n\n"));
}

static void info()
{
    fprintf( stderr , "\nwebmount " WEBMOUNT_VERSION "\n" );
}

static void license()
{
    fprintf( stderr , _("\nwebmount: mount a http url as a folder\n"
    "\n"
    "webmount is a fork from httpfs, Copyright (c) 2013 Andrea Cardaci, Emilio Pinna\n"
    "Copyright (c) 2013 Manfred Mueller <manfred.mueller@fluxflux.net>\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy of\n"
    "this software and associated documentation files (the 'Software'), to deal in\n"
    "the Software without restriction, including without limitation the rights to\n"
    "use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of\n"
    "the Software, and to permit persons to whom the Software is furnished to do so,\n"
    "subject to the following conditions:\n"
    "\n"
    "The above copyright notice and this permission notice shall be included in all\n"
    "copies or substantial portions of the Software.\n"
    "\n"
    "THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
    "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS\n"
    "FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR\n"
    "COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER\n"
    "IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN\n"
    "CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n\n"));
}

int main( int argc , char *argv[] )
{

    setlocale( LC_ALL, "" );
    bindtextdomain( "webmount", "/usr/share/locale" );
    textdomain( "webmount" );

    if ( argc == 2 && strcmp( argv[ 1 ] , "--version" ) == 0 )
    {
        info();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "-v" ) == 0 )
    {
        info();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "--help" ) == 0 )
    {
        help();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "-h" ) == 0 )
    {
        help();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "--license" ) == 0 )
    {
        license();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "-l" ) == 0 )
    {
        license();
    }
    else if ( argc == 2 && strcmp( argv[ 1 ] , "generators" ) == 0 )
    {
        const struct webmount_generator *generator;

        for ( generator = WEBMOUNT_GENERATORS ; generator->name ; generator++ )
        {
            printf( "%s\n" , generator->name );
        }
    }
    else if ( argc == 3 && strcmp( argv[ 1 ] , "generate" ) == 0 )
    {
        if ( !webmount_generate( argv[ 2 ] ) )
        {
            usage();
            return EXIT_FAILURE;
        }
    }
    else if ( ( argc == 4 ) &&
              strcmp( argv[ 1 ] , "mount" ) == 0 )
    {
        struct webmount webmount;
        const char *url;
        const char *remote_chroot;
        char *mount_point;
        int rv;

        url = argv[ 2 ];
        remote_chroot = ( "/webmount/" );
        mount_point = argv[ 3 ];

        FILE *fp;
        char str[128];
        fp = fopen("/proc/self/mounts", "r");
 
        while(fgets(str, 126, fp)) {
            if (strstr(str,mount_point) != NULL){
                 fprintf( stderr , _("\nMount point %s is in use already, exiting!\n\n"), mount_point );
                 return (6);
            }
        }  
 
        fclose(fp);

        rv = webmount_fuse_start( &webmount , url , remote_chroot , mount_point );

        if ( rv )
        {
            fprintf( stderr , _("Unable to mount: ") );

            switch ( rv )
            {
            case WEBMOUNT_FUSE_ERROR:
                fprintf( stderr , _("cannot initialize FUSE\n") );
                return(2);
                break;

            case WEBMOUNT_CURL_ERROR:
                fprintf( stderr , _("cannot initialize cURL\n") );
                return(3);
                break;

            case WEBMOUNT_UNREACHABLE_SERVER_ERROR:
                fprintf( stderr , _("cannot reach the remote server\n") );
                return(4);
                break;

            case WEBMOUNT_WRONG_CHROOT_ERROR:
                fprintf( stderr , _("cannot find the remote path\n") );
                return(5);
                break;

            case WEBMOUNT_ERRNO_ERROR:
                fprintf( stderr , _("errno (%i) %s\n") , errno , strerror( errno ) );
                return(99);
                break;
            }
        }
    }
    else
    {
        usage();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
