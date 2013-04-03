/* comment out the next line, to FULLY turn off memory debugging from this module */
//#define MEMDBG_ON

#if !defined (__MEM_DBG_H_)
#define __MEM_DBG_H_

#if defined (MEMDBG_ON)

/* uncomment the next line, to NOT free the memory. This will help track down double frees
 * and other problems. HOWEVER, it will also HIDE problems, such as using freed memory
 */
//#define MEMDBG_DANGLE_PTRs

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
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>

unsigned long   Mem_Used();
void      Mem_Display(FILE *);

void      *MEMDBG_alloc(size_t, char *, int);
void      *MEMDBG_realloc(const void *, size_t, char *, int);
void      MEMDBG_free(const void *, char *, int);
char      *MEMDBG_strdup(const char *, char *, int);

#if !defined(__MEMDBG__)
/* we get here on every file compiled EXCEPT memdbg.c */
#undef malloc
#undef realloc
#undef free
#undef strdup
#define malloc(a)     MEMDBG_alloc((a),__FILE__,__LINE__)
#define realloc(a,b)  MEMDBG_realloc((a),(b),__FILE__,__LINE__)
#define free(a)       MEMDBG_free((a),__FILE__,__LINE__)
#define strdup(a)     MEMDBG_strdup((a),__FILE__,__LINE__)
#endif

#else
/* NOTE, we DO keep one special function here.  We make free a little
 * smarter. this function gets used, even when we do NOT compile with
 * any memory debugging on. This makes free work more like C++ delete,
 * in that it is valid to call it on a NULL. Also, it sets the pointer
 * to NULL, so that we can call free(x) on x multiple times, without
 * causing a crash. NOTE, the multiple frees SHOULD be caught when
 * someone builds and runs with MEMDBG_ON. But when it is off, we do
 * try to protect the program.
 */
void MEMDBG_off_free(void *a);
#if !defined(__MEMDBG__)
#define free(a)   do { if(a) MEMDBG_off_free(a); a=0; } while(0)
#endif
extern int Mem_Used();
#define Mem_Display(a)

#endif /* MEMDBG_ON */

#endif /* __MEMDBG_H_ */
