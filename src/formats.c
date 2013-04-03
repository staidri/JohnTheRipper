/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010-2012 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JimF
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "memory.h"
#include "formats.h"
#include "misc.h"
#ifndef BENCH_BUILD
#include "options.h"
#else
#include "loader.h"
#endif
#include "memdbg.h"

/* this is just for advance_cursor() */
#ifdef HAVE_OPENCL
#include "common-opencl.h"
#elif HAVE_CUDA
#include "cuda_common.h"
#endif

struct fmt_main *fmt_list = NULL;
static struct fmt_main **fmt_tail = &fmt_list;

extern volatile int bench_running;

#ifndef BENCH_BUILD
/* We could move this to misc.c */
static size_t fmt_strnlen(const char *s, size_t max) {
    const char *p=s;
    while(*p && max--)
		++p;
    return(p - s);
}
#endif

void fmt_register(struct fmt_main *format)
{
	format->private.initialized = 0;
	format->next = NULL;
	*fmt_tail = format;
	fmt_tail = &format->next;
}

void fmt_init(struct fmt_main *format)
{
	if (!format->private.initialized) {
		format->methods.init(format);
		format->private.initialized = 1;
	}
#ifndef BENCH_BUILD
	if (options.force_maxkeys) {
		if (options.force_maxkeys <= format->params.max_keys_per_crypt)
			format->params.min_keys_per_crypt =
				format->params.max_keys_per_crypt =
				options.force_maxkeys;
		else {
			fprintf(stderr,
			    "Can't set mkpc larger than %u for %s format\n",
			    format->params.max_keys_per_crypt,
			    format->params.label);
			error();
		}
	}
	if (options.force_maxlength) {
		if (options.force_maxlength <= format->params.plaintext_length)
			format->params.plaintext_length =
				options.force_maxlength;
		else {
			fprintf(stderr, "Can't set max length larger than %u for %s format\n", format->params.plaintext_length, format->params.label);
			error();
		}
	}
#endif
}

void fmt_done(struct fmt_main *format)
{
	if (format->private.initialized) {
		format->methods.done();
		format->private.initialized = 0;
	}
}

static int is_poweroftwo(size_t align)
{
	return align != 0 && (align & (align - 1)) == 0;
}

#undef is_aligned /* clash with common.h */
static int is_aligned(void *p, size_t align)
{
	return ((size_t)p & (align - 1)) == 0;
}

static char *fmt_self_test_body(struct fmt_main *format,
    void *binary_copy, void *salt_copy)
{
	static char s_size[128];
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int i, ntests, done, index, max, size;
	void *binary, *salt;
	int binary_align_warned = 0, salt_align_warned = 0;
#ifdef DEBUG
	int validkiller = 0;
#endif
	int binary_size_warned = 0, salt_size_warned = 0;
	int ml = format->params.plaintext_length;
	char longcand[PLAINTEXT_BUFFER_SIZE];

#ifndef BENCH_BUILD
	/* UTF-8 bodge in reverse. Otherwise we will get truncated keys back */
	if ((options.utf8) && (format->params.flags & FMT_UTF8) &&
	    (format->params.flags & FMT_UNICODE))
		ml /= 3;
#endif

	// validate that there are no NULL function pointers
	if (format->methods.init == NULL)       return "method init NULL";
	if (format->methods.done == NULL)       return "method done NULL";
	if (format->methods.reset == NULL)      return "method reset NULL";
	if (format->methods.prepare == NULL)    return "method prepare NULL";
	if (format->methods.valid == NULL)      return "method valid NULL";
	if (format->methods.split == NULL)      return "method split NULL";
	if (format->methods.binary == NULL)     return "method binary NULL";
	if (format->methods.salt == NULL)       return "method salt NULL";
	if (format->methods.source == NULL)     return "method source NULL";
	if (!format->methods.binary_hash[0])    return "method binary_hash[0] NULL";
	if (format->methods.salt_hash == NULL)  return "method salt_hash NULL";
	if (format->methods.set_salt == NULL)   return "method set_salt NULL";
	if (format->methods.set_key == NULL)    return "method set_key NULL";
	if (format->methods.get_key == NULL)    return "method get_key NULL";
	if (format->methods.clear_keys == NULL) return "method clear_keys NULL";
	if (format->methods.crypt_all == NULL)  return "method crypt_all NULL";
	if (format->methods.get_hash[0]==NULL)  return "method get_hash[0] NULL";
	if (format->methods.cmp_all == NULL)    return "method cmp_all NULL";
	if (format->methods.cmp_one == NULL)    return "method cmp_one NULL";
	if (format->methods.cmp_exact == NULL)  return "method cmp_exact NULL";

/*
 * Test each format just once unless we're debugging.
 */
#ifndef DEBUG
	if (format->private.initialized == 2)
		return NULL;
#endif

	if (format->params.plaintext_length < 1 ||
	    format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "plaintext_length";

	if (!is_poweroftwo(format->params.binary_align))
		return "binary_align";

	if (!is_poweroftwo(format->params.salt_align))
		return "salt_align";

	if (format->methods.valid("*", format))
		return "valid";

	fmt_init(format);

	format->methods.reset(NULL);

	if ((format->methods.split == fmt_default_split) &&
	    (format->params.flags & FMT_SPLIT_UNIFIES_CASE))
		return "FMT_SPLIT_UNIFIES_CASE";

	if ((format->methods.binary == fmt_default_binary) &&
	    (format->params.binary_size > 0) && !binary_size_warned) {
		binary_size_warned = 1;
		puts("Warning: Using default binary() with a non-zero BINARY_SIZE");
	}
	if ((format->methods.salt == fmt_default_salt) &&
	    (format->params.salt_size > 0) && !salt_size_warned) {
		salt_size_warned = 1;
		puts("Warning: Using default salt() with a non-zero SALT_SIZE");
	}

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;
	if (ntests==0) return NULL;

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;
	do {
		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		ciphertext = format->methods.prepare(current->fields, format);
		if (!ciphertext || strlen(ciphertext) < 7)
			return "prepare";
		if (format->methods.valid(ciphertext, format) != 1)
			return "valid";

#if !defined(BENCH_BUILD) && defined(DEBUG)
		/* This defaults to disabled because it usually makes the
		   format segfault as opposed to fail the test */
		if (validkiller == 0) {
			char *killer = strdup(ciphertext);

			validkiller = 1;
			for (i = strlen(killer) - 1; i > 0; i--) {
				killer[i] = 0;
				format->methods.valid(killer, format);
			}
			MEM_FREE(killer);
		}
#endif


		if (!(ciphertext = format->methods.split(ciphertext, 0, format)))
			return "split() returned NULL";
		plaintext = current->plaintext;

/*
 * Make sure the declared binary_size and salt_size are sufficient to actually
 * hold the binary ciphertexts and salts.  We do this by copying the values
 * returned by binary() and salt() only to the declared sizes.
 */
		if (!(binary = format->methods.binary(ciphertext)))
			return "binary() returned NULL";
		if (!is_aligned(binary, format->params.binary_align) &&
		    (format->params.binary_size > 0) &&
		    !binary_align_warned) {
			puts("Warning: binary() returned misaligned pointer");
			binary_align_warned = 1;
		}
		memcpy(binary_copy, binary, format->params.binary_size);
		binary = binary_copy;

		if (!(salt = format->methods.salt(ciphertext)))
			return "salt() returned NULL";
		if (!is_aligned(salt, format->params.salt_align) &&
		    (format->params.salt_size > 0) &&
		    !salt_align_warned) {
			puts("Warning: salt() returned misaligned pointer");
			salt_align_warned = 1;
		}
		memcpy(salt_copy, salt, format->params.salt_size);
		salt = salt_copy;

		if (strcmp(ciphertext,
		    format->methods.source(ciphertext, binary)))
			return "source";

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);

		if (index == 0)
			format->methods.clear_keys();
		format->methods.set_key(current->plaintext, index);

#if !defined(BENCH_BUILD) && (defined(HAVE_OPENCL) || defined(HAVE_CUDA))
		advance_cursor();
#endif
		{
			int count = index + 1;
			if (format->methods.crypt_all(&count, NULL) != count)
				return "crypt_all";
		}

		for (size = 0; size < PASSWORD_HASH_SIZES; size++)
		if (format->methods.binary_hash[size] &&
		    format->methods.get_hash[size](index) !=
		    format->methods.binary_hash[size](binary)) {
			sprintf(s_size, "get_hash[%d](%d)", size, index);
			return s_size;
		}

		if (!format->methods.cmp_all(binary, index + 1)) {
			sprintf(s_size, "cmp_all(%d)", index + 1);
			return s_size;
		}
		if (!format->methods.cmp_one(binary, index)) {
			sprintf(s_size, "cmp_one(%d)", index);
			return s_size;
		}
		if (!format->methods.cmp_exact(ciphertext, index)) {
			sprintf(s_size, "cmp_exact(%d)", index);
			return s_size;
		}
		if (strncmp(format->methods.get_key(index), plaintext,
			format->params.plaintext_length)) {
			sprintf(s_size, "get_key(%d)", index);
			return s_size;
		}

/* Remove some old keys to better test cmp_all() */
		if (index & 1)
			format->methods.set_key("", index);

/* 0 1 2 3 4 6 9 13 19 28 42 63 94 141 211 316 474 711 1066 ... */
		if (index >= 2 && max > ntests) {
			/* Always call set_key() even if skipping. Some
			   formats depend on it. We use a max-length key
			   just to stress the format. */
			for (i = index + 1;
			     i < max && i < (index + (index >> 1)); i++) {
				memset(longcand, 'A' + (i % 23), ml);
				longcand[ml] = 0;
				format->methods.set_key(longcand, i);
			}
			index = i;
		} else
			index++;

		if (index >= max) {
			format->methods.clear_keys();
			index = (max > 5 && max > ntests && done != 1) ? 5 : 0;
			done |= 1;
		}

		if (!(++current)->ciphertext) {
/* Jump straight to last index for non-bitslice DES */
			if (!(format->params.flags & FMT_BS) &&
			    (!strcmp(format->params.label, "des") ||
			    !strcmp(format->params.label, "bsdi") ||
			    !strcmp(format->params.label, "afs")))
				index = max - 1;

			current = format->params.tests;
			done |= 2;
		}
	} while (done != 3);

#ifndef BENCH_BUILD
	/* Check that claimed max. length is actually supported:
	   1. Fill the buffer with maximum length keys */
	format->methods.clear_keys();
	for (i = 0; i < max; i++) {
		memset(longcand, 'A' + (i % 23), ml);
		longcand[ml] = 0;
		format->methods.set_key(longcand, i);
	}
	/* 2. Perform a crypt */
	{
		int count = max;
		if (format->methods.crypt_all(&count, NULL) != count)
			return "crypt_all";
	}
	/* 3. Now read them back and verify they are intact */
	for (i = 0; i < max; i++) {
		char *getkey = format->methods.get_key(i);
		memset(longcand, 'A' + (i % 23), ml);
		longcand[ml] = 0;
		if (strncmp(getkey, longcand, ml + 1)) {
			if (fmt_strnlen(getkey, ml + 1) > ml)
				sprintf(s_size, "max. length in index %d: wrote %d, got longer back", i, ml);
			else
				sprintf(s_size, "max. length in index %d: wrote %d, got %d back", i, ml, (int)strlen(getkey));
			return s_size;
		}
	}
#endif

	format->methods.clear_keys();
	format->private.initialized = 2;

	return NULL;
}

/*
 * Allocate memory for a copy of a binary ciphertext or salt with only the
 * minimum guaranteed alignment.  We do this to test that binary_hash*(),
 * cmp_*(), and salt_hash() do accept such pointers.
 */
static void *alloc_binary(void **alloc, size_t size, size_t align)
{
	size_t mask = align - 1;
	char *p;

/* Ensure minimum required alignment and leave room for "align" bytes more */
	p = *alloc = mem_alloc(size + mask + align);
	p += mask;
	p -= (size_t)p & mask;

/* If the alignment is too great, reduce it to the minimum */
	if (!((size_t)p & align))
		p += align;

	return p;
}

char *fmt_self_test(struct fmt_main *format)
{
	char *retval;
	void *binary_alloc, *salt_alloc;
	void *binary_copy, *salt_copy;

	binary_copy = alloc_binary(&binary_alloc,
	    format->params.binary_size, format->params.binary_align);
	salt_copy = alloc_binary(&salt_alloc,
	    format->params.salt_size, format->params.salt_align);

	/* We use this to keep opencl_process_event() from doing stuff
	 * while self-test is running. */
	bench_running = 1;

	retval = fmt_self_test_body(format, binary_copy, salt_copy);

	bench_running = 0;

	MEM_FREE(salt_alloc);
	MEM_FREE(binary_alloc);

	return retval;
}

void fmt_default_init(struct fmt_main *self)
{
}

void fmt_default_done(void)
{
}

void fmt_default_reset(struct db_main *db)
{
}

char *fmt_default_prepare(char *fields[10], struct fmt_main *self)
{
	return fields[1];
}

int fmt_default_valid(char *ciphertext, struct fmt_main *self)
{
	return 0;
}

char *fmt_default_split(char *ciphertext, int index, struct fmt_main *self)
{
	return ciphertext;
}

void *fmt_default_binary(char *ciphertext)
{
	return ciphertext;
}

void *fmt_default_salt(char *ciphertext)
{
	return ciphertext;
}

char *fmt_default_source(char *source, void *binary)
{
	return source;
}

int fmt_default_binary_hash(void *binary)
{
	return 0;
}

int fmt_default_salt_hash(void *salt)
{
	return 0;
}

void fmt_default_set_salt(void *salt)
{
}

void fmt_default_clear_keys(void)
{
}

int fmt_default_get_hash(int index)
{
	return 0;
}
