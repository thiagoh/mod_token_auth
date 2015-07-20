#include <cryptoc.h>
#include <stdio.h>
#include "utils.h"
#include "apr.h"
#include "apr_poll.h"
#include "util_script.h"
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

typedef struct time_duration_s time_duration_s;

struct time_duration_s {
    int duration;
    char unit; /* s, m, h, d, M */
};

typedef struct config_s config_s;
struct config_s {
    int         enabled;      /* Enable or disable our module */
    const char* secretKey;    /* Secret Key*/
    time_duration_s duration; /* How long the link might be tested as valid */
};

static config_s config;

/* Handler for the "exampleEnabled" directive */
static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg) {

	config.enabled = strcasecmp(arg, "on") == 0 || strcasecmp(arg, "yes") == 0
						|| strcasecmp(arg, "true") == 0 ? 1 : 0;
    return NULL;
}

/* Handler for the "examplePath" directive */
const char *directive_set_secret_key(cmd_parms *cmd, void *cfg, const char *arg) {

    config.secretKey = arg;
    return NULL;
}

/* Handler for the "exampleAction" directive */
/* Let's pretend this one takes one argument (file or db), and a second (deny or allow), */
/* and we store it in a bit-wise manner. */
const char *directive_set_duration(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {

	config.duration.duration = 1;
	config.duration.unit = 'm';

//    if(!strcasecmp(arg1, "file")) config.typeOfAction = 0x01;
//    else config.typeOfAction = 0x02;
//
//    if(!strcasecmp(arg2, "deny")) config.typeOfAction += 0x10;
//    else config.typeOfAction += 0x20;
    return NULL;
}

static const command_rec token_auth_directives[] = {
    AP_INIT_TAKE1("tokenAuthEnabled", directive_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_example"),
    AP_INIT_TAKE1("tokenAuthSecretKey", directive_set_secret_key, NULL, ACCESS_CONF, "The path to whatever"),
    AP_INIT_TAKE2("tokenAuthDuration", directive_set_duration, NULL, ACCESS_CONF, "Special action value!"),
    { NULL }
};
/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) {

	config.enabled = 1;
	config.duration.duration = 1;
	config.duration.unit = 'm';
	config.secretKey = 0;

	/* Hook the request handler */
	ap_hook_handler(mod_handler, NULL, NULL, APR_HOOK_LAST);
}

static void log(request_rec *r, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	//ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, fmt, __VA_ARGS__);
	va_end(args);
}

static int mod_handler(request_rec *r) {

	/* First off, we need to check if this is a call for the "example" handler.
	 * If it is, we accept it and do our things, it not, we simply return DECLINED,
	 * and Apache will try somewhere else.
	 */
	if (!r->handler || strcmp(r->handler, "token-auth-handler") || config.enabled != TRUE) {
		return DECLINED;
	}

	// The first thing we will do is write a simple "Hello, world!" back to the client.
	ap_set_content_type(r, "text/html"); /* force a raw text output */
	ap_rputs("Hello, world!<br/>\n", r);
	ap_rprintf(r, "SecretKey is: %s<br/>\n", config.secretKey);
	ap_rprintf(r, "parsed_uri.path: %s<br/>\n", r->parsed_uri.path);
	ap_rprintf(r, "parsed_uri.fragment: %s<br/>\n", r->parsed_uri.fragment);
	ap_rprintf(r, "parsed_uri.hostinfo: %s<br/>\n", r->parsed_uri.hostinfo);
	ap_rprintf(r, "parsed_uri.query: %s<br/>\n", r->parsed_uri.query);
	ap_rprintf(r, "parsed_uri.hostname: %s<br/>\n", r->parsed_uri.hostname);
	ap_rprintf(r, "parsed_uri.user: %s<br/>\n", r->parsed_uri.user);
	ap_rprintf(r, "parsed_uri.scheme: %s<br/>\n", r->parsed_uri.scheme);
	ap_rprintf(r, "request: %s<br/>\n", r->path_info);
	ap_rprintf(r, "filename: %s<br/>\n", r->filename);

	apr_table_t*GET;
	ap_args_to_table(r, &GET);

	apr_array_header_t*POST;
	ap_parse_form_data(r, NULL, &POST, -1, 8192);

	/* Get the "digest" key from the query string, if any. */
	const char *digestType = getParam(GET, "digest", "sha1");

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *plain = (unsigned char*) getParam(GET, "plain", "The fox jumped over the lazy dog");

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *cipherparam = (unsigned char*) getParam(GET, "cipher", "");

	// use const
	unsigned char *iv = (unsigned char*) "papeo fj aepojfa epfaapeof japeofj apeof ja";

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *key = (unsigned char*) getParam(GET, "key", "The fox jumped over the lazy dog");

	if (strlen((char*)key) > 0) {

		if (strlen((char*)plain) > 0) {
			cryptoc_data ciphereddata = cryptoc_encrypt(CRYPTOC_AES_192_CBC, key, iv, plain, strlen((char*)plain));

			if (!ciphereddata.error) {

				ap_rprintf(r, "Ciphered data: %s \n<br />", ciphereddata.data);
				ap_rputs("Ciphered HEX data: ", r);
				ap_rprintf_hex(r, ciphereddata.data, ciphereddata.length);
				ap_rputs("\n<br />", r);

				cryptoc_data deciphereddata = cryptoc_decrypt(CRYPTOC_AES_192_CBC, key, iv, ciphereddata.data, ciphereddata.length);

				if (!deciphereddata.error) {
					ap_rprintf(r, "DECiphered data: %s <br />", deciphereddata.data);
				} else {
					ap_rprintf(r, "Error!! %s", deciphereddata.errorMessage);
				}
			} else {
				ap_rprintf(r, "Error!! %s", ciphereddata.errorMessage);
			}
		}

		if (strlen((char*)cipherparam) > 0) {

			unsigned char* cipher = ap_hex_to_char(r, cipherparam, strlen((char*)cipherparam));

			/* The following line just prints a message to the errorlog */
			//ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "Cipher is %s / %s / %d", cipher, (cipherparam), strlen((char*)cipherparam));

			cryptoc_data deciphereddata = cryptoc_decrypt(CRYPTOC_AES_192_CBC, key, iv, cipher, strlen((char*)cipher));

			if (!deciphereddata.error) {
				ap_rprintf(r, "DECiphered data: %s <br />", deciphereddata.data);
			} else {
				ap_rprintf(r, "Error!! %s", deciphereddata.errorMessage);
			}
		}

	} else {

		/* The following line just prints a message to the errorlog */
		//ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "mod_token_auth: key is empty. %s %s", plain, cipherparam);
	}

	return OK;
}

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA mod_token_auth_module = {
	STANDARD20_MODULE_STUFF,
	NULL,            // Per-directory configuration handler
	NULL,            // Merge handler for per-directory configurations
	NULL,            // Per-server configuration handler
	NULL,            // Merge handler for per-server configurations
	token_auth_directives,            // Any directives we may have for httpd
	register_hooks   // Our hook registering function
};
