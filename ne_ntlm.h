/*
   Handling of NTLM Authentication
   Copyright (C) 2003, Daniel Stenberg <daniel at haxx.se>

   SSH-NTLM Adaptations
   Copyright (C) 2003, Laurence A. Lee (lalee_net@yahoo.com)

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
#ifndef NE_NTLM_H
#define NE_NTLM_H

typedef enum {
  NTLMSTATE_NONE,
  NTLMSTATE_TYPE1,
  NTLMSTATE_TYPE2,
  NTLMSTATE_TYPE3,
  NTLMSTATE_LAST
} NENTLM_PROXYSTATE;

typedef enum {
  NENTLM_NONE, /* not a ntlm */
  NENTLM_BAD,  /* an ntlm, but one we don't like */
  NENTLM_FIRST, /* the first 401-reply we got with NTLM */
  NENTLM_FINE, /* an ntlm we act on */

  NENTLM_LAST  /* last entry in this enum, don't use */
} NENTLM_STATUS;

/* Struct used for NTLM challenge-response authentication */
struct ntlmdata {
  NENTLM_PROXYSTATE state;
  unsigned char nonce[8];
};

//----------------------------------------
// Begin Lalee's Ugly Hacks
//----------------------------------------
typedef int bool;
typedef enum {
  NENTLME_OK,
  NENTLME_OUT_OF_MEMORY
} NENTLM_CODE;

//Adapt the expect routine from connect.c
int expect( char *str, char *substr); //from connect.c
int checkprefix( char *str, char *substr); //wrapper for connect.c's expect()

struct SessionHandle {
  char foobarbaz[8];  //What's this structure do? -- Lalee
};

// Define a compatible "connectdata" structure.
struct connectdata {
  struct ntlmdata proxyntlm;
  struct ntlmdata ntlm;
  char* proxyuser;
  char* user;
  char* proxypasswd;
  char* passwd;
  //
  struct SessionHandle* data;
  //
  struct dynamically_allocated_data {
    char* proxyuserpwd;
    char* userpwd;
    //
  } allocptr;
};

// Other Ugly-Hack (Wrapper) functions, defined at end of ne_ntlm.c
void ne_safefree(void* p);
void ne_http_auth_stage(struct SessionHandle *data,int stage);
char* aprintf(char* format, ...);

//----------------------------------------
// End of Lalee's Ugly Hacks
//----------------------------------------

/* this is for ntlm header input */
NENTLM_STATUS ne_input_ntlm(struct connectdata *conn, bool proxy, char *header);

/* this is for creating ntlm header output */
NENTLM_CODE ne_output_ntlm(struct connectdata *conn, bool proxy);

void ne_ntlm_cleanup(struct SessionHandle *data);

/* Flag bits definitions based on http://davenport.sourceforge.net/ntlm.html */

#define NTLMFLAG_NEGOTIATE_UNICODE               (1<<0)
/* Indicates that Unicode strings are supported for use in security buffer
   data. */

#define NTLMFLAG_NEGOTIATE_OEM                   (1<<1)
/* Indicates that OEM strings are supported for use in security buffer data. */

#define NTLMFLAG_REQUEST_TARGET                  (1<<2)
/* Requests that the server's authentication realm be included in the Type 2
   message. */

/* unknown (1<<3) */
#define NTLMFLAG_NEGOTIATE_SIGN                  (1<<4)
/* Specifies that authenticated communication between the client and server
   should carry a digital signature (message integrity). */

#define NTLMFLAG_NEGOTIATE_SEAL                  (1<<5)
/* Specifies that authenticated communication between the client and server
   should be encrypted (message confidentiality). */

#define NTLMFLAG_NEGOTIATE_DATAGRAM_STYLE        (1<<6)
/* unknown purpose */

#define NTLMFLAG_NEGOTIATE_LM_KEY                (1<<7)
/* Indicates that the LAN Manager session key should be used for signing and
   sealing authenticated communications. */

#define NTLMFLAG_NEGOTIATE_NETWARE               (1<<8)
/* unknown purpose */

#define NTLMFLAG_NEGOTIATE_NTLM_KEY              (1<<9)
/* Indicates that NTLM authentication is being used. */

/* unknown (1<<10) */
/* unknown (1<<11) */

#define NTLMFLAG_NEGOTIATE_DOMAIN_SUPPLIED       (1<<12)
/* Sent by the client in the Type 1 message to indicate that a desired
   authentication realm is included in the message. */

#define NTLMFLAG_NEGOTIATE_WORKSTATION_SUPPLIED  (1<<13)
/* Sent by the client in the Type 1 message to indicate that the client
   workstation's name is included in the message. */

#define NTLMFLAG_NEGOTIATE_LOCAL_CALL            (1<<14)
/* Sent by the server to indicate that the server and client are on the same
   machine. Implies that the client may use a pre-established local security
   context rather than responding to the challenge. */

#define NTLMFLAG_NEGOTIATE_ALWAYS_SIGN           (1<<15)
/* Indicates that authenticated communication between the client and server
   should be signed with a "dummy" signature. */

#define NTLMFLAG_TARGET_TYPE_DOMAIN              (1<<16)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a domain. */

#define NTLMFLAG_TARGET_TYPE_SERVER              (1<<17)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a server. */

#define NTLMFLAG_TARGET_TYPE_SHARE               (1<<18)
/* Sent by the server in the Type 2 message to indicate that the target
   authentication realm is a share. Presumably, this is for share-level
   authentication. Usage is unclear. */

#define NTLMFLAG_NEGOTIATE_NTLM2_KEY             (1<<19)
/* Indicates that the NTLM2 signing and sealing scheme should be used for
   protecting authenticated communications. */

#define NTLMFLAG_REQUEST_INIT_RESPONSE           (1<<20)
/* unknown purpose */

#define NTLMFLAG_REQUEST_ACCEPT_RESPONSE         (1<<21)
/* unknown purpose */

#define NTLMFLAG_REQUEST_NONNT_SESSION_KEY       (1<<22)
/* unknown purpose */

#define NTLMFLAG_NEGOTIATE_TARGET_INFO           (1<<23)
/* Sent by the server in the Type 2 message to indicate that it is including a
   Target Information block in the message. */

/* unknown (1<24) */
/* unknown (1<25) */
/* unknown (1<26) */
/* unknown (1<27) */
/* unknown (1<28) */

#define NTLMFLAG_NEGOTIATE_128                   (1<<29)
/* Indicates that 128-bit encryption is supported. */

#define NTLMFLAG_NEGOTIATE_KEY_EXCHANGE          (1<<30)
/* unknown purpose */

#define NTLMFLAG_NEGOTIATE_56                    (1<<31)
/* Indicates that 56-bit encryption is supported. */
#endif
