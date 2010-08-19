/*
   Handling of NTLM Authentication
   Copyright (C) 2003, Daniel Stenberg <daniel at haxx.se>

   SSH-NTLM Adaptations
   Copyright (C) 2003-2005, Laurence A. Lee (lalee_net@yahoo.com)

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

/* NTLM details:

   http://davenport.sourceforge.net/ntlm.html
   http://www.innovation.ch/java/ntlm.html

*/
#include "ne_ntlm.h" // Added by Lalee
#include "base64.h"  // Added by Lalee

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>


#ifdef USE_SSLEAY
  /* We need OpenSSL for the crypto lib to provide us with MD4 and DES */
  #include <openssl/des.h>
  #include <openssl/md4.h>
  #include <openssl/ssl.h>

  #if OPENSSL_VERSION_NUMBER < 0x00907001L
  #define DES_key_schedule des_key_schedule
  #define DES_cblock des_cblock
  #define DES_set_odd_parity des_set_odd_parity
  #define DES_set_key des_set_key
  #define DES_ecb_encrypt des_ecb_encrypt

  /* This is how things were done in the old days */
  #define DESKEY(x) x
  #define DESKEYARG(x) x
  #else
  /* Modern version */
  #define DESKEYARG(x) *x
  #define DESKEY(x) &x
  #endif

  DES_key_schedule nentlm_des_context;
  #define nentlm_setdeskey(context,key) DES_set_key((DES_cblock*)key, context)

  #define nentlm_des_ecb_encrypt(context,plaintext,results) des_ecb_encrypt((DES_cblock*)plaintext,(DES_cblock*)results,context,DES_ENCRYPT)
#else
  #include "des.h" // Added by Lalee
  des_ctx nentlm_des_context;
  #define nentlm_setdeskey(context,key) des_setkey(*context,key)
  #define nentlm_des_ecb_encrypt(context,plaintext,results) des_ecb_encrypt(context,plaintext,results)
#endif

/* Define this to make the type-3 message include the NT response message */
//#undef USE_NTRESPONSES

/*
  (*) = A "security buffer" is a triplet consisting of two shorts and one
  long:

  1. a 'short' containing the length of the buffer in bytes
  2. a 'short' containing the allocated space for the buffer in bytes
  3. a 'long' containing the offset to the start of the buffer from the
     beginning of the NTLM message, in bytes.
*/

NENTLM_STATUS ne_input_ntlm(struct connectdata *conn,
                       bool proxy,   /* if proxy or not */
                       char *header) /* rest of the www-authenticate:
                                        header */
{
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;

  ntlm = proxy?&conn->proxyntlm:&conn->ntlm;

  /* skip initial whitespaces */
  while(*header && isspace((int)*header))
    header++;

  if(checkprefix("NTLM", header)) {
    unsigned char buffer[256];
    header += strlen("NTLM");



    while(*header && isspace((int)*header))
      header++;

    if(*header) {
      /* We got a type-2 message here:

         Index   Description         Content
         0       NTLMSSP Signature   Null-terminated ASCII "NTLMSSP"
                                     (0x4e544c4d53535000)
         8       NTLM Message Type   long (0x02000000)
         12      Target Name         security buffer(*)
         20      Flags               long
         24      Challenge           8 bytes
         (32)    Context (optional)  8 bytes (two consecutive longs)
         (40)    Target Information  (optional) security buffer(*)
         32 (48) start of data block
      */

      int size = base64_decode(header, buffer);

      ntlm->state = NTLMSTATE_TYPE2; /* we got a type-2 */
      if(size >= 48) {
        /* the nonce of interest is index [24 .. 31], 8 bytes */
        memcpy(ntlm->nonce, &buffer[24], 8);

//memset(ntlm->nonce,0xAA,8);
        debug("### ne_input_ntlm:  Using NONCE:  [%02X%02X%02X%02X%02X%02X%02X%02X]\n",
            ntlm->nonce[0],ntlm->nonce[1],ntlm->nonce[2],ntlm->nonce[3],
            ntlm->nonce[4],ntlm->nonce[5],ntlm->nonce[6],ntlm->nonce[7]
            );
      }
      /* at index decimal 20, there's a 32bit NTLM flag field */
    }
    else {
      if(ntlm->state > NTLMSTATE_TYPE1) {
        return NENTLM_BAD;
      }
      ntlm->state = NTLMSTATE_TYPE1; /* we should sent away a type-1 */
    }
  }
  return NENTLM_FINE;
}

// Converts a 56bit DES Key to 64bits.
void keys56to64(unsigned char* key56,unsigned char* key64) {
  key64[0] =   key56[0];
  key64[1] = ((key56[0] << 7) & 0xFF) | (key56[1] >> 1);
  key64[2] = ((key56[1] << 6) & 0xFF) | (key56[2] >> 2);
  key64[3] = ((key56[2] << 5) & 0xFF) | (key56[3] >> 3);
  key64[4] = ((key56[3] << 4) & 0xFF) | (key56[4] >> 4);
  key64[5] = ((key56[4] << 3) & 0xFF) | (key56[5] >> 5);
  key64[6] = ((key56[5] << 2) & 0xFF) | (key56[6] >> 6);
  key64[7] =  (key56[6] << 1) & 0xFF;
#ifdef USE_SSLEAY
  DES_set_odd_parity((DES_cblock*)key64);
#endif
  debug("### keys56to64:  56BitKey = [%02X%02X%02X%02X%02X%02X%02X%02X]\n",
    key56[0],key56[1],key56[2],key56[3],
    key56[4],key56[5],key56[6],key56[7]
    );
  debug("### keys56to64:  64BitKey = [%02X%02X%02X%02X%02X%02X%02X%02X]\n",
    key64[0],key64[1],key64[2],key64[3],
    key64[4],key64[5],key64[6],key64[7]
    );
}

 /*
  * takes a 21 byte array and treats it as 3 56-bit DES keys. The
  * 8 byte plaintext is encrypted with each key and the resulting 24
  * bytes are stored in the results array.
  */
static void calc_resp(unsigned char *keys56,
                      unsigned char *plaintext,
                      unsigned char *results)
{
  unsigned char keys64[24];

  debug("### calc_resp:  plaintext = [%02X%02X%02X%02X%02X%02X%02X%02X]\n",
    plaintext[0],plaintext[1],plaintext[2],plaintext[3],
    plaintext[4],plaintext[5],plaintext[6],plaintext[7]
    );

  keys56to64(&keys56[ 0],&keys64[ 0]);
  keys56to64(&keys56[ 7],&keys64[ 8]);
  keys56to64(&keys56[14],&keys64[16]);

  //Pass 1
    nentlm_setdeskey(&nentlm_des_context,&keys64[0]);
    nentlm_des_ecb_encrypt(nentlm_des_context,plaintext,&results[0]);

  //Pass 2
    nentlm_setdeskey(&nentlm_des_context,&keys64[8]);
    nentlm_des_ecb_encrypt(nentlm_des_context,plaintext,&results[8]);

  //Pass 3
    nentlm_setdeskey(&nentlm_des_context,&keys64[16]);
    nentlm_des_ecb_encrypt(nentlm_des_context,plaintext,&results[16]);

  debug("### calc_resp:  CipherText = [%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X]\n",
    results[ 0],results[ 1],results[ 2],results[ 3],results[ 4],results[ 5],results[ 6],results[ 7],
    results[ 8],results[ 9],results[10],results[11],results[12],results[13],results[14],results[15],
    results[16],results[17],results[18],results[19],results[20],results[21],results[22],results[23]
    );
}

/*
 * Set up lanmanager and nt hashed passwords
 */
static void mkhash(char *password,
                   unsigned char *nonce,  /* 8 bytes */
                   unsigned char *lmresp  /* must fit 0x18 bytes */
#ifdef USE_NTRESPONSES
                   , unsigned char *ntresp  /* must fit 0x18 bytes */
#endif
  )
{
  unsigned char lmbuffer[21];
#ifdef USE_NTRESPONSES
  unsigned char ntbuffer[21];
#endif
  unsigned char *pw;
  static const unsigned char magic[] = {
    0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25
  };
  int i;
  int len = strlen(password);

  /* make it fit at least 14 bytes */
  pw = malloc(len<7?14:len*2);
  memset(pw,0,14); // Lalee:  Better safe than sorry -- fill it with zeros.

  if(!pw)
    return; /* this will lead to a badly generated package */

  if (len > 14)
    len = 14;

  for (i=0; i<len; i++)
    pw[i] = toupper(password[i]);

  for (; i<14; i++)
    pw[i] = 0;

  {
    unsigned char keys64[24];

    keys56to64(pw+00,&keys64[0]);
    keys56to64(pw+07,&keys64[8]);

  //Pass 1
    nentlm_setdeskey(&nentlm_des_context,&keys64[0]);
    nentlm_des_ecb_encrypt(nentlm_des_context,magic,&lmbuffer[0]);

  //Pass 2
    nentlm_setdeskey(&nentlm_des_context,&keys64[8]);
    nentlm_des_ecb_encrypt(nentlm_des_context,magic,&lmbuffer[8]);

  //Pad last 5 bytes with zeros
    memset(lmbuffer+16,0,5);
  }

  /* create LM responses */
  calc_resp(lmbuffer, nonce, lmresp);

#ifdef USE_NTRESPONSES
  {
    /* create NT hashed password */
    MD4_CTX MD4;

    len = strlen(password);

    for (i=0; i<len; i++) {
      pw[2*i]   = password[i];
      pw[2*i+1] = 0;
    }

    MD4_Init(&MD4);
    MD4_Update(&MD4, pw, 2*len);
    MD4_Final(ntbuffer, &MD4);

    memset(ntbuffer+16, 0, 8);
  }
  calc_resp(ntbuffer, nonce, ntresp);
#endif
  free(pw);
}

#define SHORTPAIR(x) ((x) & 0xff), ((x) >> 8)
#define LONGQUARTET(x) ((x) & 0xff), (((x) >> 8)&0xff), \
  (((x) >>16)&0xff), ((x)>>24)

/* this is for creating ntlm header output */
NENTLM_CODE ne_output_ntlm(struct connectdata *conn,
                          bool proxy)
{
  const char *domain=""; /* empty */
  const char *host=""; /* empty */

  int domlen=strlen(domain);
  int hostlen = strlen(host);
  int hostoff; /* host name offset */
  int domoff;  /* domain name offset */
  int size;
  char *base64=NULL;
  unsigned char ntlmbuf[256]; /* enough, unless the host/domain is very long */

  /* point to the address of the pointer that holds the string to sent to the
     server, which is for a plain host or for a HTTP proxy */
  char **allocuserpwd;

  /* point to the name and password for this */
  char *userp;
  char *passwdp;
  /* point to the correct struct with this */
  struct ntlmdata *ntlm;

  if(proxy) {
    allocuserpwd = &conn->allocptr.proxyuserpwd;
    userp = conn->proxyuser;
    passwdp = conn->proxypasswd;
    ntlm = &conn->proxyntlm;
  }
  else {
    allocuserpwd = &conn->allocptr.userpwd;
    userp = conn->user;
    passwdp = conn->passwd;
    ntlm = &conn->ntlm;
  }

  if(!userp || !passwdp) {
    /* no user, no auth */
    return NENTLME_OK;
  }

  switch(ntlm->state) {
  case NTLMSTATE_TYPE1:
  default: /* for the weird cases we (re)start here */
    hostoff = 32;
    domoff = hostoff + hostlen;

    /* Create and send a type-1 message:

    Index Description          Content
    0     NTLMSSP Signature    Null-terminated ASCII "NTLMSSP"
                               (0x4e544c4d53535000)
    8     NTLM Message Type    long (0x01000000)
    12    Flags                long
    16    Supplied Domain      security buffer(*)
    24    Supplied Workstation security buffer(*)
    32    start of data block

    */
    snprintf((char *)ntlmbuf, sizeof(ntlmbuf), "NTLMSSP%c"
             "\x01%c%c%c" /* 32-bit type = 1 */
             "%c%c%c%c"   /* 32-bit NTLM flag field */
             "%c%c"  /* domain length */
             "%c%c"  /* domain allocated space */
             "%c%c"  /* domain name offset */
             "%c%c"  /* 2 zeroes */
             "%c%c"  /* host length */
             "%c%c"  /* host allocated space */
             "%c%c"  /* host name offset */
             "%c%c"  /* 2 zeroes */
             "%s"   /* host name */
             "%s",  /* domain string */
             0,     /* trailing zero */
             0,0,0, /* part of type-1 long */

             LONGQUARTET(
               NTLMFLAG_NEGOTIATE_OEM|      /*   2 */
               NTLMFLAG_NEGOTIATE_NTLM_KEY  /* 200 */
               /* equals 0x0202 */
               ),

             SHORTPAIR(domlen),
             SHORTPAIR(domlen),
             SHORTPAIR(domoff),
             0,0,
             SHORTPAIR(hostlen),
             SHORTPAIR(hostlen),
             SHORTPAIR(hostoff),
             0,0,
             host, domain);

    /* initial packet length */
    size = 32 + hostlen + domlen;

    /* now keeper of the base64 encoded package size */
    size = base64_encode(ntlmbuf, size, &base64);

    if(size >0 ) {
      ne_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sConnection: Keep-Alive\r\n%sAuthorization: NTLM %s\r\n",
                              proxy?"Proxy-":"",
                              proxy?"Proxy-":"",
                              base64);
      free(base64);
    }
    else
      return NENTLME_OUT_OF_MEMORY; /* FIX TODO */
    break;

  case NTLMSTATE_TYPE2:
    /* We received the type-2 already, create a type-3 message:

    Index   Description            Content
    0       NTLMSSP Signature      Null-terminated ASCII "NTLMSSP"
                                   (0x4e544c4d53535000)
    8       NTLM Message Type      long (0x03000000)
    12      LM/LMv2 Response       security buffer(*)
    20      NTLM/NTLMv2 Response   security buffer(*)
    28      Domain Name            security buffer(*)
    36      User Name              security buffer(*)
    44      Workstation Name       security buffer(*)
    (52)    Session Key (optional) security buffer(*)
    (60)    Flags (optional)       long
    52 (64) start of data block

    */
  {
    int lmrespoff;
    int ntrespoff;
    int useroff;
    unsigned char lmresp[0x18]; /* fixed-size */
#ifdef USE_NTRESPONSES
    unsigned char ntresp[0x18]; /* fixed-size */
#endif
    const char *user;
    int userlen;

    user = strchr(userp, '\\');
    if(!user)
      user = strchr(userp, '/');

    if (user) {
      domain = userp;
      domlen = user - domain;
      user++;
    }
    else
      user = userp;
    userlen = strlen(user);
    mkhash(passwdp, &ntlm->nonce[0], lmresp
#ifdef USE_NTRESPONSES
           , ntresp
#endif
      );

    domoff = 64; /* always */
    useroff = domoff + domlen;
    hostoff = useroff + userlen;
    lmrespoff = hostoff + hostlen;
    ntrespoff = lmrespoff + 0x18;

    /* Create the big type-3 message binary blob */
    size = snprintf((char *)ntlmbuf, sizeof(ntlmbuf),
                    "NTLMSSP%c"
                    "\x03%c%c%c" /* type-3, 32 bits */

                    "%c%c%c%c" /* LanManager length + allocated space */
                    "%c%c" /* LanManager offset */
                    "%c%c" /* 2 zeroes */

                    "%c%c" /* NT-response length */
                    "%c%c" /* NT-response allocated space */
                    "%c%c" /* NT-response offset */
                    "%c%c" /* 2 zeroes */

                    "%c%c"  /* domain length */
                    "%c%c"  /* domain allocated space */
                    "%c%c"  /* domain name offset */
                    "%c%c"  /* 2 zeroes */

                    "%c%c"  /* user length */
                    "%c%c"  /* user allocated space */
                    "%c%c"  /* user offset */
                    "%c%c"  /* 2 zeroes */

                    "%c%c"  /* host length */
                    "%c%c"  /* host allocated space */
                    "%c%c"  /* host offset */
                    "%c%c%c%c%c%c"  /* 6 zeroes */

                    "\xff\xff"  /* message length */
                    "%c%c"  /* 2 zeroes */

                    "\x01\x82" /* flags */
                    "%c%c"  /* 2 zeroes */

                    /* domain string */
                    /* user string */
                    /* host string */
                    /* LanManager response */
                    /* NT response */
                    ,
                    0, /* zero termination */
                    0,0,0, /* type-3 long, the 24 upper bits */

                    SHORTPAIR(0x18),  /* LanManager response length, twice */
                    SHORTPAIR(0x18),
                    SHORTPAIR(lmrespoff),
                    0x0, 0x0,

#ifdef USE_NTRESPONSES
                    SHORTPAIR(0x18),  /* NT-response length, twice */
                    SHORTPAIR(0x18),
#else
                    0x0, 0x0,
                    0x0, 0x0,
#endif
                    SHORTPAIR(ntrespoff),
                    0x0, 0x0,

                    SHORTPAIR(domlen),
                    SHORTPAIR(domlen),
                    SHORTPAIR(domoff),
                    0x0, 0x0,

                    SHORTPAIR(userlen),
                    SHORTPAIR(userlen),
                    SHORTPAIR(useroff),
                    0x0, 0x0,

                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostlen),
                    SHORTPAIR(hostoff),
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0,

                    0x0, 0x0,

                    0x0, 0x0);

    /* size is now 64 */
    size=64;
    ntlmbuf[62]=ntlmbuf[63]=0;

    memcpy(&ntlmbuf[size], domain, domlen);
    size += domlen;

    memcpy(&ntlmbuf[size], user, userlen);
    size += userlen;

    memcpy(&ntlmbuf[size], host, hostlen);
    size += hostlen;

    /* we append the binary hashes to the end of the blob */
    if(size < ((int)sizeof(ntlmbuf) - 0x18)) {
      memcpy(&ntlmbuf[size], lmresp, 0x18);
      size += 0x18;
    }

#ifdef USE_NTRESPONSES
    if(size < ((int)sizeof(ntlmbuf) - 0x18)) {
      memcpy(&ntlmbuf[size], ntresp, 0x18);
      size += 0x18;
    }
#endif

    ntlmbuf[56] = size & 0xff;
    ntlmbuf[57] = size >> 8;

    /* convert the binary blob into base64 */
    size = base64_encode(ntlmbuf, size, &base64);

    if(size >0 ) {
      ne_safefree(*allocuserpwd);
      *allocuserpwd = aprintf("%sAuthorization: NTLM %s\r\n",
                              proxy?"Proxy-":"",
                              base64);
      free(base64);
    }
    else
      return NENTLME_OUT_OF_MEMORY; /* FIX TODO */

    ntlm->state = NTLMSTATE_TYPE3; /* we sent a type-3 */

    /* Switch to web authentication after proxy authentication is done */
    if (proxy)
      ne_http_auth_stage(conn->data, 401);
  }
  break;

  case NTLMSTATE_TYPE3:
    /* connection is already authenticated,
     * don't send a header in future requests */
    if(*allocuserpwd) {
      free(*allocuserpwd);
      *allocuserpwd=NULL;
    }
    break;
  }

  return NENTLME_OK;
}

//--- START OF UGLY HACKS (WRAPPERS) BY LALEE ---

void ne_safefree(void* p) {
  if (p) { free(p); }
}

void ne_http_auth_stage(struct SessionHandle *data,int stage) {
 // do nothing . . .
}

char* aprintf(char* format, ...) {
  va_list ap_save; // argument pointer
  int numchars;
  char* ret;

  va_start(ap_save, format);
  numchars = vasprintf(&ret, format, ap_save);
  va_end(ap_save);

  return ret;
}

//Adapt the expect routine from connect.c...
int checkprefix( char *str, char *substr) {
  return !expect(str,substr);
}

//--- END OF UGLY HACKS BY LALEE ---
