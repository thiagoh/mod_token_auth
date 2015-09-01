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

void _free_crypto_data(cryptoc_data* deciphereddata, unsigned char* dataDecoded, unsigned char* ivDecoded) {

	free(dataDecoded);
	free(ivDecoded);

	free(deciphereddata->data);
	free(deciphereddata->tag);
	free(deciphereddata->errorMessage);
}

static int mod_handler_debug(request_rec *r) {

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
	const unsigned char *iv = (unsigned char*) "aefpojaefojaepfojaepaoejfapeojfaeopjaej";
	long ivlength = strlen((char*)iv);

	/* Get the "digest" key from the query string, if any. */
	// use const
	unsigned char *key = (unsigned char*) getParam(GET, "key", "The fox jumped over the lazy dog");
	long keylength = strlen((char*)key);

	if (strlen((char*)key) > 0) {

		if (strlen((char*)plain) > 0) {
			cryptoc_data ciphereddata = cryptoc_encrypt_iv(CRYPTOC_AES_192_CBC, key, keylength, iv, ivlength, plain, strlen((char*)plain));

			if (!ciphereddata.error) {

				ap_rprintf(r, "Ciphered data: %s \n<br />", ciphereddata.data);
				ap_rputs("Ciphered HEX data: ", r);
				ap_rprintf_hex(r, ciphereddata.data, ciphereddata.length);
				ap_rputs("\n<br />", r);

				cryptoc_data deciphereddata = cryptoc_decrypt_iv(CRYPTOC_AES_192_CBC, key, keylength, iv, ivlength, ciphereddata.data, ciphereddata.length);

				if (!deciphereddata.error) {
					deciphereddata.data[deciphereddata.length] = '\0';

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

			cryptoc_data deciphereddata = cryptoc_decrypt_iv(CRYPTOC_AES_192_CBC, key, keylength, iv, ivlength, cipher, strlen((char*)cipher));

			if (!deciphereddata.error) {
				deciphereddata.data[deciphereddata.length] = '\0';

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

static int mod_handler_execute(request_rec *r) {

	apr_table_t*GET;
	ap_args_to_table(r, &GET);

	/* Get the "digest" key from the query string, if any. */
	const char *token = getParam(GET, "token", "");
	size_t tokenLength = strlen((char*)token);

	if (tokenLength == 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "no token");
		return DECLINED;
	}

	long keylength = strlen((char*) config.secretKey);

	unsigned char* dataDecoded = 0;
	unsigned char* ivDecoded = 0;
	cryptoc_data* deciphereddata = 0;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "0");

	deciphereddata = (cryptoc_data*) malloc(sizeof(cryptoc_data));

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "1");

	if (!deciphereddata) {
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "2");

	dataDecoded = (unsigned char*) malloc(sizeof(unsigned char) * tokenLength);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "3");

	if (!dataDecoded) {
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "4");

	int dataDecodedLen = cryptoc_base64_decode(token, tokenLength, dataDecoded);

	unsigned char* ivEncoded = (unsigned char *) "dGFyZ2V0AAA=";
	unsigned char* key= (unsigned char *) "The fox jumped over the lazy dog";

	ivDecoded = (unsigned char*) malloc(sizeof(unsigned char) * strlen((const char*)ivEncoded));

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "5");

	if (!ivDecoded) {
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "6");

	int ivDecodedLen = cryptoc_base64_decode(ivEncoded, strlen((const char*)ivEncoded), ivDecoded);
	*deciphereddata = cryptoc_decrypt_iv(CRYPTOC_DES_EDE3_CBC, config.secretKey, keylength, ivDecoded, ivDecodedLen, dataDecoded, dataDecodedLen);

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "7");

	if (deciphereddata->error) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Deciphering error: %s", deciphereddata->errorMessage);
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "8");

	unsigned char* finalData = 0;
	finalData = (unsigned char*) malloc(sizeof(unsigned char) * deciphereddata->length + 1);

	if (!finalData){
		return DECLINED;
	}

	strncpy(finalData, deciphereddata->data, deciphereddata->length);
	finalData[deciphereddata->length + 1] = '\0';

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Deciphering data: %s", finalData);
	_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);

	return OK;
}

static int mod_handler(request_rec *r) {

	/* First off, we need to check if this is a call for the "example" handler.
	 * If it is, we accept it and do our things, it not, we simply return DECLINED,
	 * and Apache will try somewhere else.
	 */
	if (!r->handler || (!strcmp(r->handler, "token-auth-handler") && !strcmp(r->handler, "token-auth-handler-debug")) || config.enabled != TRUE) {
//		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "no matching");
		return DECLINED;
	}

	if (!strcmp(r->handler, "token-auth-handler")) {
		return mod_handler_execute(r);

	} else if (!strcmp(r->handler, "token-auth-handler-debug")) {
		return mod_handler_debug(r);
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
