#include <crypto.h>
#include <string.h>
#include "time.h"
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {

    (void) state; /* unused */
}

/* A test case that does nothing and succeeds. */
static void simple_test_success(void **state) {

	long current_time; // real call is required here
	time(&current_time);

	/* A 256 bit key */
	unsigned char *key = (unsigned char *) "any256bitkey_chars_to_complete_0";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *) "any128bitkey_000";

	unsigned char* plain = (unsigned char *) "Se hoje é o dia das crianças... Ontem eu disse: o dia da criança é o dia da mãe, dos pais, das professoras, mas também é o dia dos animais, sempre que você olha uma criança, há sempre uma figura oculta, que é um cachorro atrás. O que é algo muito importante!"; //"the fox jumped over the lazy dog";

	crypto_data cipheredPair = crypto_encrypt(plain, strlen((char*) plain), key, iv);
	crypto_data decipheredPair = crypto_decrypt(cipheredPair.data, cipheredPair.length, key, iv);

	assert_int_equal(strlen((char*) plain), decipheredPair.length);
	assert_string_equal(plain, decipheredPair.data);
}

int main(void) {

	long current_time; // real call is required here
	time(&current_time);

	printf("Test initialization... %ld", current_time);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(simple_test_success),
    };

    int results = cmocka_run_group_tests(tests, NULL, NULL);

	time(&current_time);
    printf("Test teardown %ld", current_time);

    return results;
}
