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
#include <string.h>
#include "webmount.h"

static size_t retrieve_chunk( char *ptr ,
                              size_t size ,
                              size_t nmemb ,
                              void *userdata )
{
    struct raw_data *data;
    size_t chunk_size;

    chunk_size = size * nmemb;
    data = ( struct raw_data * )userdata;
    data->payload = realloc( data->payload , data->size + chunk_size );
    memcpy( data->payload + data->size , ptr , chunk_size );
    data->size += chunk_size;

    return chunk_size;
}

CURLcode webmount_do_post( struct webmount *webmount ,
                         const struct raw_data *in ,
                         struct raw_data *out )
{
    CURL *curl;

    out->payload = malloc( 1 );
    out->size = 0;

    curl = webmount->curl;
    curl_easy_setopt( curl , CURLOPT_URL , webmount->url );
    curl_easy_setopt( curl , CURLOPT_POSTFIELDS , in->payload );
    curl_easy_setopt( curl , CURLOPT_POSTFIELDSIZE , in->size );
    curl_easy_setopt( curl , CURLOPT_WRITEFUNCTION , retrieve_chunk );
    curl_easy_setopt( curl , CURLOPT_WRITEDATA , out );

    return curl_easy_perform( curl );
}
