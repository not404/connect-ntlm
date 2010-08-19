// --------------------------------------------------------
//Lalee:  Copied Stuff from GnuPG's types.h
// --------------------------------------------------------

/* The AC_CHECK_SIZEOF() in configure fails for some machines.
 * we provide some fallback values here */
#if !SIZEOF_UNSIGNED_SHORT
#undef SIZEOF_UNSIGNED_SHORT
#define SIZEOF_UNSIGNED_SHORT 2
#endif
#if !SIZEOF_UNSIGNED_INT
#undef SIZEOF_UNSIGNED_INT
#define SIZEOF_UNSIGNED_INT 4
#endif
#if !SIZEOF_UNSIGNED_LONG
#undef SIZEOF_UNSIGNED_LONG
#define SIZEOF_UNSIGNED_LONG 4
#endif

#ifndef HAVE_U32_TYPEDEF
#undef u32	    /* maybe there is a macro with this name */
#if SIZEOF_UNSIGNED_INT == 4
typedef unsigned int u32;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long u32;
#else
#error no typedef for u32
#endif
#define HAVE_U32_TYPEDEF
#endif

#ifndef HAVE_BYTE_TYPEDEF
#undef byte	    /* maybe there is a macro with this name */
#ifndef __riscos__
typedef unsigned char byte;
#else 
/* Norcroft treats char  = unsigned char  as legal assignment
               but char* = unsigned char* as illegal assignment
   and the same applies to the signed variants as well  */
typedef char byte;
#endif
#define HAVE_BYTE_TYPEDEF
#endif

// --------------------------------------------------------
//Lalee:  Copied Stuff from GnuPG's util.h
// --------------------------------------------------------

#define wipememory2(_ptr,_set,_len) do { volatile char *_vptr=(volatile char *)(_ptr); size_t _vlen=(_len); while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)

// --------------------------------------------------------
//Lalee:  Copied Stuff from GnuPG's errors.h
// --------------------------------------------------------

#define G10ERR_WEAK_KEY       43 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_WRONG_KEYLEN   44 /* NOTE: hardcoded into the cipher modules */
#define G10ERR_SELFTEST_FAILED 50

// --------------------------------------------------------
//Lalee:  Moved stuff from GnuPG's des.c
// --------------------------------------------------------

typedef struct _des_ctx
  {
    u32 encrypt_subkeys[32];
    u32 decrypt_subkeys[32];
  }
des_ctx[1];

int des_setkey (struct _des_ctx *, const byte *);
int des_ecb_crypt (struct _des_ctx *, const byte *, byte *, int);

/*
 * Handy macros for encryption and decryption of data
 */
#define des_ecb_encrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 0)
#define des_ecb_decrypt(ctx, from, to)		des_ecb_crypt(ctx, from, to, 1)
#define tripledes_ecb_encrypt(ctx, from, to)	tripledes_ecb_crypt(ctx, from, to, 0)
#define tripledes_ecb_decrypt(ctx, from, to)	tripledes_ecb_crypt(ctx, from, to, 1)

// --------------------------------------------------------
// --------------------------------------------------------
