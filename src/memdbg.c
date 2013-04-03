/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

/*
 *  memdbg.c
 *  Memory management debugging (at runtime)
 *
 *   memdbg.c contains routines detect, and report memory
 *   problems, such as double frees, passing bad pointers to
 *   free, most buffer overwrites.  Also, tracking of non-freed
 *   data, showing memory leaks, can also be shown.
 *
 *  Compilation Options (in the memdbg.h file)
 *
 *   MEMDBG_ON     If this is NOT defined, then memdbg will
 *       get out of your way, and most normal memory functions
 *       will be called with no overhead at all.
 *
 *   MEMDBG_DANGLE_PTRs   If defined, then we do not 'really' free
 *       the memory.  We simply set the tag to deleted status,
 *       and proceed.  This allows us finding double frees, and other
 *       usages of smashes.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#define __MEMDBG__
#include "memdbg.h"

#if defined (MEMDBG_ON)

#define MEMTAG   0xa5a5a5a5
#define MEMTAGd  0x5a5a5a5a
const char *cpMEMTAG = "\xa5\xa5\xa5\xa5";

/*
 * this structure will contain data that is butted RIGHT against
 * the tail end of the allocated block. We put a fence post here,
 * and thus can detect buffer overwrite.
 */
typedef struct _hdr2 {
	unsigned char mdbg_tag[4];
} MEMDBG_HDR2;

/*
 *  This structure is carefully crafted. It contains exactly
 *  4 32 bit values (possibly 6 on non-aligned hw), and 4 pointers
 *  In the end, we should have alignment as good as we would
 *  get from the allocator. This puts our mdbg_tag2 RIGHT against
 *  the start of the allocated block.  We later will put the
 *  HDR2 RIGHT against the tail end of the buffer.  This will
 *  allow us to catch a single byte over or underflow.
 */
typedef struct _hdr {
   struct _hdr *mdbg_next;
   struct _hdr *mdbg_prev;
   const char*  mdbg_file;
   MEMDBG_HDR2 *mdbg_hdr2;
   ARCH_WORD_32 mdbg_size;
   ARCH_WORD_32 mdbg_line;
   ARCH_WORD_32 mdbg_cnt;
   ARCH_WORD_32 mdbg_tag;
} MEMDBG_HDR;

static unsigned long   mem_size = 0;
static MEMDBG_HDR     *memlist = NULL;
static ARCH_WORD_32   alloc_cnt = 0;

/*
 * This function can be called directly by client code.
 * it lists how much memory is currently allocated.
 * a good check before program exit, is are there 0
 * bytes allocated.
 */
unsigned long Mem_Used() {
	return mem_size;
}

/*
 * This function can be called directly by client code.
 * It writes out all non-freed memory.
 */
void Mem_Display(FILE *fp) {
	MEMDBG_HDR *p;
	int idx;

	fprintf(fp, "Index : alloc# : Size   : File(Line) - total size %lu\n", mem_size);
	idx = 0;
	p = memlist;
	while (p != NULL) {
		fprintf(fp, "%-5d : %-6d : %6u : %s(%d)", idx++, p->mdbg_cnt, p->mdbg_size, p->mdbg_file, p->mdbg_line);
		if (p->mdbg_tag != MEMTAG) {
			if (p->mdbg_tag == MEMTAGd)
				fprintf(fp, " INVALID ( freed already? )");
			else
				fprintf(fp, " INVALID ( buffer underflow )");

		}
		if (memcmp(p->mdbg_hdr2, cpMEMTAG, 4))
			fprintf(fp, " INVALID (buffer overflow)");
		fprintf(fp, "\n");
		p = p->mdbg_next;
	}
}

#define RESERVE_SZ (sizeof(MEMDBG_HDR))

#define CLIENT_2_HDR(a) ((MEMDBG_HDR *) (((char *) (a)) - RESERVE_SZ))
#define HDR_2_CLIENT(a) ((void *) (((char *) (a)) + RESERVE_SZ))

static void   mem_tag_err(void *, char *, int);
static void   mem_tag_errd(void *, char *, int);
static void   MEMDBG_LIST_add(MEMDBG_HDR *);
static void   MEMDBG_LIST_delete(MEMDBG_HDR *);

/*
 *  MEMDBG_alloc
 *  Allocate a memory block. makes a protected call to malloc(), allocating
 *  extra data, and adding data to all required structures.
 */
void * MEMDBG_alloc(size_t size, char *file, int line)
{
	MEMDBG_HDR      *p;

	p = (MEMDBG_HDR*)malloc(RESERVE_SZ + size + 4);
	if (p == NULL)
		return NULL;
	p->mdbg_tag = MEMTAG;
	p->mdbg_size = size;
	p->mdbg_cnt = ++alloc_cnt;
	mem_size += size;
	p->mdbg_file = file;
	p->mdbg_line = line;
	p->mdbg_hdr2 = (MEMDBG_HDR2*)(((char*)p)+RESERVE_SZ + size);
	memcpy(p->mdbg_hdr2, cpMEMTAG, 4);
	MEMDBG_LIST_add(p);
	return HDR_2_CLIENT(p);
}

/*
 *  MEMDBG_realloc
 *  Reallocate a memory block makes a protected call to realloc(), allocating
 *  extra data, and adding data to all required structures.
 */
void *
MEMDBG_realloc(const void *ptr, size_t size, char *file, int line)
{
	MEMDBG_HDR      *p;

	p = CLIENT_2_HDR(ptr);
	if (p->mdbg_tag != MEMTAG || memcmp(p->mdbg_hdr2, cpMEMTAG, 4)) {
		if (p->mdbg_tag == MEMTAGd)
			mem_tag_errd(p, file, line);
		else
			mem_tag_err(p, file, line);
		return NULL;
	}
	p->mdbg_tag = MEMTAGd;
	mem_size -= p->mdbg_size;
	MEMDBG_LIST_delete(p);
	if (size == 0) {
#if !defined (MEMDBG_DANGLE_PTRs)
		free(p);
#endif
		return NULL;
	}
	p = (MEMDBG_HDR *) realloc(p, RESERVE_SZ + size + 4);
	if (p == NULL)
		return NULL;
	p->mdbg_tag = MEMTAG;
	p->mdbg_size = size;
	p->mdbg_cnt = ++alloc_cnt;
	mem_size += size;
	p->mdbg_file = file;
	p->mdbg_line = line;
	p->mdbg_hdr2 = (MEMDBG_HDR2*)(((char*)p)+RESERVE_SZ + size);
	memcpy(p->mdbg_hdr2, cpMEMTAG, 4);
	MEMDBG_LIST_add(p);
	return HDR_2_CLIENT(p);
}

/*
 *  MEMDBG_strdup
 *  Duplicate a ASCIIZ string in memory, with a protected call to strdup,
 *  allocating extra data, and adding data to all required structures.
 */
char *MEMDBG_strdup(const char *str, char *file, int line)
{
	char * s;
	s = (char*)MEMDBG_alloc(strlen(str)+1, file, line);
	if (s != NULL)
		strcpy(s, str);
	return s;
}

/*
 *  MEMDBG_free
 *  Free a memory block, checking a lot of data, which would have been
 *  set at allocation time.
 */
void MEMDBG_free(const void *ptr, char *file, int line)
{
	MEMDBG_HDR       *p;

	p = CLIENT_2_HDR(ptr);
	if (p->mdbg_tag != MEMTAG || memcmp(p->mdbg_hdr2, cpMEMTAG, 4)) {
		if (p->mdbg_tag == MEMTAGd)
			mem_tag_errd(p, file, line);
		else
			mem_tag_err(p, file, line);
		return;
	}
	p->mdbg_tag = MEMTAGd;
	mem_size -= p->mdbg_size;
	MEMDBG_LIST_delete(p);
#if !defined (MEMDBG_DANGLE_PTRs)
	free(p);
#endif
}

static void MEMDBG_LIST_add(MEMDBG_HDR *p)
{
	p->mdbg_next = memlist;
	p->mdbg_prev = NULL;
	if (memlist != NULL)
		memlist->mdbg_prev = p;
	memlist = p;

#if defined(DEBUG_LIST)
	printf("MEMDBG_LIST_add()\n");
	Mem_Display(stdout);
#endif
}

static void MEMDBG_LIST_delete(MEMDBG_HDR *p)
{
	if (p->mdbg_next != NULL)
		p->mdbg_next->mdbg_prev = p->mdbg_prev;
	if (p->mdbg_prev != NULL)
		p->mdbg_prev->mdbg_next = p->mdbg_next;
	else
		memlist = p->mdbg_next;

#if defined(DEBUG_LIST)
	printf("MEMDBG_LIST_delete()\n");
	Mem_Display(stdout);
#endif
}
static void mem_tag_err(void *p, char *file, int line)
{
	fprintf(stderr, "Memory tag error - %p - %s(%d)\n", p, file, line);
	Mem_Display(stderr);
	exit(1);
}
static void mem_tag_errd(void *p, char *file, int line)
{
	fprintf(stderr, "Memory tag error, using dangling pointer, memory already freed - %p - %s(%d)\n", p, file, line);
	Mem_Display(stderr);
	exit(1);
}

#else

void MEMDBG_off_free(void *a) {
	free(a);
}
int Mem_Used() {
	return 0;
}
#endif // MEMDBG_ON
