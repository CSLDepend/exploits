#ifndef _ICONV_H
#define _ICONV_H

#include <sys/cdefs.h>
#include <sys/types.h>

/* Identifier for conversion method from one codeset to another.  */
typedef unsigned int iconv_t;

/* Allocate descriptor for code conversion from codeset FROMCODE to
   codeset TOCODE.  */
extern iconv_t iconv_open (const char *tocode, const char *fromcode) __THROW;

/* Convert at most *INBYTESLEFT bytes from *INBUF according to the
   code conversion algorithm specified by CD and place up to
   *OUTBYTESLEFT bytes in buffer at *OUTBUF.  */
extern size_t iconv (iconv_t cd, const char** inbuf,
		     size_t* inbytesleft,
		     char** outbuf,
		     size_t* outbytesleft) __THROW;

/* Free resources allocated for descriptor CD for code conversion.  */
extern int iconv_close (iconv_t cd) __THROW;

#endif /* iconv.h */
