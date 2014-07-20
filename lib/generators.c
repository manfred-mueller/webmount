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

#include <stdio.h>
#include "webmount.h"
#include "generators.h"

const struct webmount_generator WEBMOUNT_GENERATORS[] = {
#define _( x ) { #x , webmount_generate_##x } ,
#include "generators.def"
    { NULL , NULL }
};

int webmount_generate( const char *name )
{
    const struct webmount_generator *generator;

    for ( generator = WEBMOUNT_GENERATORS ; generator->name ; generator++ )
    {
        if ( strcmp( generator->name , name ) == 0 )
        {
            generator->function();
            return 1;
        }
    }

    return 0;
}

void webmount_generate_php()
{
#include "template.php.h"
    int i;
    const char **p;

    /* opcode names array */
    printf( "<?php\n\n" );
    printf( "$WEBMOUNT_OPCODE_NAMES = array(\n" );

    for ( p = WEBMOUNT_OPCODE_NAMES ; *p ; p++ )
    {
        printf( "    'webmount_%s' ,\n" , *p );
    }

    printf( ");\n\n" );

    /* status codes numeric constants */
    for ( p = WEBMOUNT_STATUS_NAMES ; *p ; p++ )
    {
        printf( "define( '%s' , %i );\n" ,
                *p , ( int )( p - WEBMOUNT_STATUS_NAMES ) );
    }

    /* verbose mode */
    if ( WEBMOUNT_VERBOSE ) printf( "\ndefine( 'VERBOSE' , TRUE );\n\n" );

    printf( "\n?>" );

    /* dump template */
    for ( i = 0 ; i < template_php_len ; i++ )
    {
        fputc( template_php[ i ] , stdout );
    }
}
