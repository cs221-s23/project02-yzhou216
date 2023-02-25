#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "passwords.h"
#include "sha256.h"

#define DIG_BIN_LEN 32
#define DIG_STR_LEN ((DIG_BIN_LEN * 2))

/* define the length of passwords dictionary */
#define DICT_LEN (sizeof(passwords) / sizeof(passwords[0]))
#define PASSWD_MAX_LEN 64

#define ARGC_MAX 4
#define ARGC_MIN 3

void sha256(char *dest, char *src)
{
	/* zero out the sha256 context */
	struct sha256_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	/* zero out the binary version of the hash digest */
	unsigned char dig_bin[DIG_BIN_LEN];
	memset(dig_bin, 0, DIG_BIN_LEN);

	/* zero out the string version of the hash digest */
	memset(dest, 0, DIG_STR_LEN + 1);

	/* compute the binary hash digest */
	__sha256_init_ctx(&ctx);
	__sha256_process_bytes(src, strlen(src), &ctx);
	__sha256_finish_ctx(&ctx, dig_bin);

	/* convert it into a string of hexadecimal digits */
	for (int i = 0; i < DIG_BIN_LEN; i++) {
		snprintf(dest, 3, "%02x", dig_bin[i]);
		dest += 2;
	}
}

char *dig(char *str)
{
	char *res = (char *) malloc((DIG_STR_LEN + 1) * sizeof(char));
	sha256(res, str);
	return res;
}

char *leet(char *str)
{
	char *res = (char *) malloc((strlen(str) + 1) * sizeof(char));
	for (int i = 0; i < strlen(str); i++) {
		switch (str[i]) {
			case 'o':
				res[i] = '0';
				break;
			case 'e':
				res[i] = '3';
				break;
			case 'i':
				res[i] = '!';
				break;
			case 'a':
				res[i] = '@';
				break;
			case 'h':
				res[i] = '#';
				break;
			case 's':
				res[i] = '$';
				break;
			case 't':
				res[i] = '+';
				break;
			default:
				res[i] = str[i];
		}
	}
	return res;
}

char *add_one(char *str)
{
	/*
	 * Allocate memory for the result to be one byte more than the source
	 * string for the addition of the charactor '1' at the end.
	 */
	char *res = (char *) malloc((strlen(str) + 2) * sizeof(char));
	/* length of the res string excluding the NULL terminator */
	int res_len = strlen(str) + 1;
	memset(res, 0, res_len + 1);
	strncpy(res, str, res_len);
	strncat(res, "1", res_len);
	return res;
}

struct entry {
	char passwd[PASSWD_MAX_LEN + 1];
	char dig_str[DIG_STR_LEN + 1];
	struct entry *next;
} entry;

int duplicated_dig_str(char *str) {
	/*
	 * determine whether hash digest of leetified string is the same as hash
	 * digest of plaintext string
	 */
	char *leet_str = leet(str);
	if (!strcmp(leet_str, str)) {
		free(leet_str);
		return 0;
	}
	free(leet_str);
	return 1;
}

struct entry *create_plaintext_node(char *passwd) {
	char *dig_str;

	struct entry *pair = malloc(sizeof(struct entry));
	if (!pair) {
		printf("malloc failed\n");
		exit(-1);
	}
	memset(pair, 0, sizeof(struct entry));

	strncpy(pair->passwd, passwd, PASSWD_MAX_LEN);
	dig_str = dig(passwd);
	strncpy(pair->dig_str, dig_str, DIG_STR_LEN);
	free(dig_str);

	return pair;
}

struct entry *create_leet_node(char *passwd) {
	char *leet_str;
	char *dig_str;

	struct entry *pair = malloc(sizeof(struct entry));
	if (!pair) {
		printf("malloc failed\n");
		exit(-1);
	}
	memset(pair, 0, sizeof(struct entry));

	leet_str = leet(passwd);
	strncpy(pair->passwd, leet_str, PASSWD_MAX_LEN);
	dig_str = dig(leet_str);
	free(leet_str);
	strncpy(pair->dig_str, dig_str, DIG_STR_LEN);
	free(dig_str);

	return pair;
}

struct entry *create_add_one_node(char *passwd) {
	char *add_one_str;
	char *dig_str;

	struct entry *pair = malloc(sizeof(struct entry));
	if (!pair) {
		printf("malloc failed\n");
		exit(-1);
	}
	memset(pair, 0, sizeof(struct entry));

	add_one_str = add_one(passwd);
	strncpy(pair->passwd, add_one_str, PASSWD_MAX_LEN);
	dig_str = dig(add_one_str);
	free(add_one_str);
	strncpy(pair->dig_str, dig_str, DIG_STR_LEN);
	free(dig_str);

	return pair;
}

void add_node(struct entry **head, struct entry *node) {
	if (*head == NULL) {
		*head = node;
		return;
	}
	struct entry *cur = *head;
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = node;
}

void print_list(struct entry *head) {
	while (head) {
		printf("%s\n", head->passwd);
		head = head->next;
	}
}

void arg_check(int argc, char **argv,
	       char **fpath_passwds,
	       char **fpath_dict,
	       int *verbose) {

	*fpath_passwds = argv[1];
	*fpath_dict = argv[2];

	char *vflag = argv[3];

	if (argc <= ARGC_MAX && argc >= ARGC_MIN) {
		goto vflag_check;
	} else {
		if (argc < ARGC_MIN) {
			printf("not enough arguments\n");
			exit(-1);
		}
		if (argc > ARGC_MAX) {
			printf("too many arguments\n");
			exit(-1);
		}
	}

vflag_check:
	if (argc == 4) {
		if (!strcmp(vflag, "-v") || !strcmp(vflag, "--verbose")) {
			*verbose = 0;
		} else {
			printf("invalid arguments\n");
			exit(-1);
		}

	}
}

int main(int argc, char **argv)
{
	char *fpath_passwds;
	char *fpath_dict;
	int verbose = 1;
	arg_check(argc, argv, &fpath_passwds, &fpath_dict, &verbose);

	struct entry *head = NULL;

	for (int i = 0; i < DICT_LEN; i++) {
		struct entry *plaintext_pair
			     = create_plaintext_node(passwords[i]);
		plaintext_pair->next = NULL;
		add_node(&head, plaintext_pair);

		if (duplicated_dig_str(passwords[i])) {
			struct entry *leet_pair
				     = create_leet_node(passwords[i]);
			plaintext_pair->next = NULL;
			add_node(&head, leet_pair);
		}

		struct entry *add_one_pair = create_add_one_node(passwords[i]);
		add_one_pair->next = NULL;
		add_node(&head, add_one_pair);
	}
	print_list(head);

	return 0;
}
