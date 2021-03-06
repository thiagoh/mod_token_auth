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

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

/* Prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int mod_handler(request_rec *r);

typedef struct time_duration_s time_duration_s;

struct time_duration_s {
    int duration;
    char unit; /* s, m, h, d, M */
};

typedef struct config_s config_s;
struct config_s {
    int         enabled;		/* Enable or disable our module */
    int			debugLevel;		/* Sets the debug level */
    const char* algorithm;		/* Used algorithm */
    const char* secretKey;		/* Secret Key */
    const char* tokenParam;		/* Token param (default is token) */
    const char* iv;    			/* Secret Key */
    time_duration_s duration;	/* How long the link might be tested as valid */
};

static config_s config;

/* Handler for the "exampleEnabled" directive */
static const char *directive_set_enabled(cmd_parms *cmd, void *cfg, const char *arg) {

	config.enabled = strcasecmp(arg, "on") == 0 || strcasecmp(arg, "yes") == 0
						|| strcasecmp(arg, "true") == 0 ? 1 : 0;
    return NULL;
}

/* Handler for the "secretKey" directive */
const char *directive_set_secret_key(cmd_parms *cmd, void *cfg, const char *arg) {

    config.secretKey = arg;
    return NULL;
}

/* Handler for the "TokenParam" directive */
const char *directive_set_token_param(cmd_parms *cmd, void *cfg, const char *arg) {

    config.tokenParam = arg;
    return NULL;
}

/* Handler for the "iv" directive */
const char *directive_set_iv(cmd_parms *cmd, void *cfg, const char *arg) {

    config.iv = arg;
    return NULL;
}

/* Handler for the "algorithm" directive */
const char *directive_set_algorithm(cmd_parms *cmd, void *cfg, const char *arg) {

    config.algorithm = arg;

    if (!strcasecmp(config.algorithm, "aes") && !strcasecmp(config.algorithm, "desede")) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, cmd->server, "No such algorithm %s exists", config.algorithm);
		return DECLINED;
	}

    return NULL;
}

/* Handler for the "debug" directive */
const char *directive_set_debug_level(cmd_parms *cmd, void *cfg, const char *arg) {

    config.debugLevel = atoi(arg);
    return NULL;
}

/* Handler for the "duration" directive */
const char *directive_set_duration(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {

	config.duration.duration = 1;
	config.duration.unit = 'm';
    return NULL;
}

static const command_rec token_auth_directives[] = {
    AP_INIT_TAKE1("tokenAuthEnabled", directive_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_token_auth"),
    AP_INIT_TAKE1("tokenAuthSecretKey", directive_set_secret_key, NULL, ACCESS_CONF, "The secret key"),
    AP_INIT_TAKE1("tokenAuthIV", directive_set_iv, NULL, ACCESS_CONF, "The initialization vector"),
    AP_INIT_TAKE1("tokenAuthTokenParam", directive_set_token_param, NULL, ACCESS_CONF, "The token param"),
    AP_INIT_TAKE1("tokenAuthAlgorithm", directive_set_algorithm, NULL, ACCESS_CONF, "The algorithm to be used"),
    AP_INIT_TAKE1("tokenAuthDebug", directive_set_debug_level, NULL, ACCESS_CONF, "The debug level"),
    AP_INIT_TAKE2("tokenAuthDuration", directive_set_duration, NULL, ACCESS_CONF, "Special action value!"),
    { NULL }
};
/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) {

	config.enabled = 1;
	config.debugLevel = 0;
	config.duration.duration = 1;
	config.duration.unit = 'm';
	config.secretKey = 0;
	config.tokenParam = 0;
	config.iv = 0;
	config.algorithm = 0;

	/* Hook the request handler */
	ap_hook_handler(mod_handler, NULL, NULL, APR_HOOK_LAST);
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

	if (config.secretKey) {
		ap_rprintf(r, "SecretKey is: %s<br/>\n", config.secretKey);
	}

	if (config.iv) {
		ap_rprintf(r, "IV is: %s<br/>\n", config.iv);
	}

	if (config.tokenParam) {
		ap_rprintf(r, "TokenParam is: %s<br/>\n", config.tokenParam);
	}

	if (config.algorithm) {
		ap_rprintf(r, "Algorithm is: %s<br/>\n", config.algorithm);
	}

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

	if (!config.secretKey) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such secretKey set");
		return DECLINED;
	}

	if (!config.iv) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such IV set");
		return DECLINED;
	}

	if (!config.algorithm) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such algorithm set");
		return DECLINED;
	}

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

	if (!config.secretKey) {
		if (config.debugLevel >= 1) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such secretKey set");
		}
		return DECLINED;
	}

	if (!config.iv) {
		if (config.debugLevel >= 1) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such IV set");
		}
		return DECLINED;
	}

	if (!config.algorithm) {
		if (config.debugLevel >= 1) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such algorithm set");
		}
		return DECLINED;
	}

	if (!strcasecmp(config.algorithm, "aes") && !strcasecmp(config.algorithm, "desede")) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such algorithm %s exists", config.algorithm);
		}
		return DECLINED;
	}

	apr_table_t*GET;
	ap_args_to_table(r, &GET);

	const char* tokenParam = config.tokenParam == 0 ? "token" : config.tokenParam;
	const char *token = getParam(GET, tokenParam, "");
	size_t tokenLength = strlen((char*)token);

	if (tokenLength == 0) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "No such token passed");
		}
		return DECLINED;
	}

	const unsigned char* key = config.secretKey;
	const unsigned char* ivEncoded = config.iv;
	int ivEncodedLen = strlen((char*) config.iv);
	long keylength = strlen((char*) config.secretKey);
	unsigned char* ivDecoded = 0;
	int ivDecodedLen = 0;
	unsigned char* dataDecoded = 0;
	int dataDecodedLen = 0;
	cryptoc_data* deciphereddata = 0;

	if (config.debugLevel >= 3) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Process started");
	}

	deciphereddata = (cryptoc_data*) malloc(sizeof(cryptoc_data));

	if (!deciphereddata) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not allocate memory for decrypt data");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	dataDecoded = (unsigned char*) malloc(sizeof(unsigned char) * tokenLength);

	if (!dataDecoded) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not allocate memory for decoded data");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	dataDecodedLen = cryptoc_base64_decode(token, tokenLength, dataDecoded);

	if (!dataDecodedLen || !dataDecoded) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not base64 decode data");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	if (config.debugLevel >= 3) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server, "Data decoded successfully");
	}

	ivDecoded = (unsigned char*) malloc(sizeof(unsigned char) * strlen((const char*)ivEncoded));

	if (!ivDecoded) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not allocate memory for IV");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	ivDecodedLen = cryptoc_base64_decode(ivEncoded, strlen((const char*)ivEncoded), ivDecoded);

	if (!ivDecodedLen || !ivDecoded) {
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not base64 decode IV");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	if (config.debugLevel >= 3) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server, "IV decoded successfully");
	}

	*deciphereddata = cryptoc_decrypt_iv(CRYPTOC_DES_EDE3_CBC, key, keylength, ivDecoded, ivDecodedLen, dataDecoded, dataDecodedLen);

	if (!deciphereddata || deciphereddata->error) {
		if (deciphereddata) {
			if (config.debugLevel >= 2) {
				ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Deciphering error: %s", deciphereddata->errorMessage);
			}
		} else {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Deciphering error: unknown error");
		}
		_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);
		return DECLINED;
	}

	if (config.debugLevel >= 3) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server, "Data decrypted successfully");
	}

	unsigned char* finalData = 0;
	finalData = (unsigned char*) malloc(sizeof(unsigned char) * deciphereddata->length + 1);

	if (!finalData){
		if (config.debugLevel >= 2) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Could not allocate final data");
		}
		return DECLINED;
	}

	strncpy(finalData, deciphereddata->data, deciphereddata->length);
	finalData[deciphereddata->length + 1] = '\0';

	if (config.debugLevel >= 2) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server, "Final data copied successfully. Decrypted data: %s", finalData);
	}

	_free_crypto_data(deciphereddata, dataDecoded, ivDecoded);

	if (config.debugLevel >= 3) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->server, "Process finished");
	}

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
