#include <crypto.h>
#include "utils.h"

char* getParam(apr_table_t* GET, const char* key, const char* default_) {

	/* Get the key from the query string, if any. */
	const char *value = apr_table_get(GET, key);

	/* If no key was returned, we will set a default value instead. */
	if (!value)
		value = default_;

	return (char*) value;
}

void _print(const unsigned char* s, int length) {

	for (int i = 0; i < length; i++) {
		printf("%x", 0xFF & s[i]);
	}
}

char* _sprint(const unsigned char* s, int length) {

	char* sout = (char*) malloc(sizeof(char*) * (length + 1));
	int i;
	for (i = 0; i < length; i++) {
		sprintf(sout + i, "%02x", s[i]);
	}
	sout[i + 1] = '\0';
	return sout;
}

unsigned char* ap_hex_to_char(request_rec *r, unsigned const char* s, int length) {

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
	while(i < length && sscanf((const char*) s + i, "%02x", soutp++) == 1) {
		i+=2;
	}
	*(++soutp)= '\0';
	return sout;
}

void ap_rprintf_hex(request_rec *r, unsigned const char* s, int length) {

	for (int i = 0; i < length; i++) {
		ap_rprintf(r, "%02x", s[i]);
	}
}
