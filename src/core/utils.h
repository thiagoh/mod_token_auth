/*
 * utils.h
 *
 *  Created on: Jul 18, 2015
 *      Author: thiago
 */

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <stdio.h>
#include "apr.h"
#include "apr_poll.h"
#include "apr_hash.h"
#include "apr_pools.h"
#include "ap_config.h"
#include "ap_provider.h"
/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

char* getParam(apr_table_t* GET, const char* key, const char* default_);
void print(const unsigned char* s, int length);
const char* sprint(const unsigned char* s, int length);
unsigned char* ap_hex_to_char(request_rec *r, unsigned const char* s, int length);
void ap_rprintf_hex(request_rec *r, const unsigned char* s, int length);

#endif /* SRC_UTILS_H_ */
