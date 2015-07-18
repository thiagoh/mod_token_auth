#include <crypto.h>
#include <stdio.h>
#include "utils.h"
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
static int mod_handler(request_rec *r);

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA mod_token_auth_module = {
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
	ap_hook_handler(mod_handler, NULL, NULL, APR_HOOK_LAST);
}

/* The handler function for our module.
 * This is where all the fun happens!
 */

static int mod_handler(request_rec *r) {

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
