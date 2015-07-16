#include <crypto.h>
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

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int example_handler(request_rec *r);

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA example_module = {

STANDARD20_MODULE_STUFF,
NULL,            // Per-directory configuration handler
		NULL,            // Merge handler for per-directory configurations
		NULL,            // Per-server configuration handler
		NULL,            // Merge handler for per-server configurations
		NULL,            // Any directives we may have for httpd
		register_hooks   // Our hook registering function
		};

/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) {

	/* Hook the request handler */
	ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_LAST);
}

/* The handler function for our module.
 * This is where all the fun happens!
 */

static char* getParam(apr_table_t* GET, char* key, char* default_) {

	/* Get the key from the query string, if any. */
	char *value = apr_table_get(GET, key);

	/* If no key was returned, we will set a default value instead. */
	if (!value)
		value = default_;

	return value;
}

static void _print(const unsigned char* s, int length) {

	for (int i = 0; i < length; i++) {
		printf("%x", 0xFF & s[i]);
	}
}

static char* _sprint(const unsigned char* s, int length) {

	char* sout = malloc(sizeof(char*) * (length + 1));
	int i;
	for (i = 0; i < length; i++) {
		sprintf(sout + i, "%02x", s[i]);
	}
	sout[i + 1] = '\0';
	return sout;
}

static unsigned char* ap_hex_to_char(request_rec *r, const unsigned char* s, int length) {

	// Navigating through pointers: mode 1
	// this mode uses an integer to increment the position
//	unsigned char* sout = (unsigned char*) malloc(sizeof(unsigned char*) * (length + 1));
//	int i = 0;
//	int id = 0;
//	while(i < length) {
//
//		int out = sscanf(s + i, "%02x", sout + id++);
//		//sout += sizeof(unsigned char);
//		char buf[40];
//		sprintf(buf, "line: %d %p, %p", i, sout, sout + id);
//		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "%s", buf);
//
//		if (out != 1) {
//			break;
//		}
//
//		i += 2;
//	}
//	sout[i + 1] = '\0';
//	return sout;

	// Navigating through pointers: mode 2
	// this mode doesnt use an auxiliar pointer. It goes forward and then backwards
//	unsigned char* sout = (unsigned char*) malloc(sizeof(unsigned char*) * (length + 1));
//	int i = 0;
//	int id = 0;
//	while(i < length) {
//
//		int out = sscanf(s + i, "%02x", sout++);
//
//		char buf[40];
//		sprintf(buf, "line: %d %p", i, sout);
//		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "%s", buf);
//
//		if (out != 1) {
//			break;
//		}
//
//		i+=2;
//	}
//	sout++;
//	*sout = '\0';
//	while(length > 0) {
//		sout--;
//		length -= 2;
//	}
//	sout--;
//	return sout;

	// Navigating through pointers: mode 3
	// this mode uses an auxiliar pointer
//	//http://www.c4learn.com/c-programming/c-incrementing-pointer/
//	unsigned char* sout = (unsigned char*) malloc(sizeof(unsigned char*) * (length + 1));
//	unsigned char* soutp = sout;
//	int i = 0;
//	while(i < length) {
//
//		int out = sscanf(s + i, "%02x", soutp++);
//
//		char buf[40];
//		sprintf(buf, "line: %d %p", i, soutp);
//		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "%s", buf);
//
//		if (out != 1) {
//			break;
//		}
//
//		i+=2;
//	}
//	soutp++;
//	*soutp = '\0';
//	return sout;

	// Navigating through pointers: mode 4 (equal to 3 but improved)
	// this mode uses an auxiliar pointer
	//http://www.c4learn.com/c-programming/c-incrementing-pointer/
	unsigned char* sout = (unsigned char*) malloc(sizeof(unsigned char*) * (length + 1));
	unsigned char* soutp = sout;
	int i = 0;
	while(i < length && sscanf(s + i, "%02x", soutp++) == 1) {
		i+=2;
	}
	*(++soutp)= '\0';
	return sout;
}

static void ap_rprintf_hex(request_rec *r, const unsigned char* s, int length) {

	for (int i = 0; i < length; i++) {
		ap_rprintf(r, "%02x", s[i]);
	}
}

static int example_handler(request_rec *r) {

	/* First off, we need to check if this is a call for the "example" handler.
	 * If it is, we accept it and do our things, it not, we simply return DECLINED,
	 * and Apache will try somewhere else.
	 */
	if (!r->handler || strcmp(r->handler, "example-handler"))
		return (DECLINED);

	// The first thing we will do is write a simple "Hello, world!" back to the client.
	ap_set_content_type(r, "text/html"); /* force a raw text output */
	ap_rputs("Hello, world!<br/>", r);

	apr_table_t*GET;
	ap_args_to_table(r, &GET);

	apr_array_header_t*POST;
	ap_parse_form_data(r, NULL, &POST, -1, 8192);

	/* Get the "digest" key from the query string, if any. */
	const char *digestType = getParam(GET, "digest", "sha1");

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *plain = getParam(GET, "plain", "The fox jumped over the lazy dog");

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *cipherparam = getParam(GET, "cipher", "");

	// use const
	unsigned char *iv = "papeo fj aepojfa epfaapeof japeofj apeof ja";

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *key = getParam(GET, "key", "The fox jumped over the lazy dog");

	if (strlen(key) > 0) {

		if (strlen(plain) > 0) {
			crypto_data ciphereddata = crypto_encrypt(plain, strlen(plain), key, iv);

			ap_rprintf(r, "Ciphered data: %s \n<br />", ciphereddata.data);
			ap_rputs("Ciphered HEX data: ", r);
			ap_rprintf_hex(r, ciphereddata.data, ciphereddata.length);
			ap_rputs("\n<br />", r);

			crypto_data deciphereddata = crypto_decrypt(ciphereddata.data, ciphereddata.length, key, iv);
			ap_rprintf(r, "DECiphered data: %s <br />", deciphereddata.data);
		}

		if (strlen(cipherparam) > 0) {

			unsigned char* cipher = ap_hex_to_char(r, cipherparam, strlen(cipherparam));

			/* The following line just prints a message to the errorlog */
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server,
					"Cipher is %s / %s / %d", cipher, (cipherparam), strlen(cipherparam));

			crypto_data deciphereddata = crypto_decrypt(cipher, strlen(cipher), key, iv);
			ap_rprintf(r, "DECiphered data: %s <br />", deciphereddata.data);
		}

	} else {

		/* The following line just prints a message to the errorlog */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server,
				"mod_token_auth: key is empty. %s %s", plain, cipherparam);

	}

	return OK;
}
