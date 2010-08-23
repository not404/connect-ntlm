/*
    Base64 Implementation
    Copyright (C) 2003, Laurence A. Lee (lalee_net@yahoo.com)

    This file is part of SSH-NTLM.

    SSH-NTLM is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    SSH-NTLM is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SSH-NTLM; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include "base64.h"
#include "stdlib.h"
#include "string.h"
//--------------------------------------------------------------------------------------------
// Helper Routines . . .
//--------------------------------------------------------------------------------------------
  const char *B64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  int Un64(char ch) {
    if ((ch>='A') && (ch<='Z')) { return (ch-'A'); }
    if ((ch>='a') && (ch<='z')) { return (ch-'a') + 26; }
    if ((ch>='0') && (ch<='9')) { return (ch-'0') + 52; }
    if ((ch=='+')             ) { return 62; }
    if ((ch=='/')             ) { return 63; }
    return -1;
  }
//--------------------------------------------------------------------------------------------
// Primary Routines . . .
//--------------------------------------------------------------------------------------------

  int base64_encode(void* in, int size, char **out) {
    int i,j; // indexes into Src and Dest

    int pad = (size % 3);
    int numQuantums = (size-pad)/3 + ((pad>0)?1:0);
    int ret = numQuantums * 4;
    char* dest;
    char* src = in;

    //Allocate a suitable buffer . . .
        dest = (char*)malloc(ret + 1);
        *out = dest;
        dest[ret] = 0; //Enforce a Zero-Padded String.
    //Process the Non-Padded Parts . . .
      for (i=0,j=0;i<(size-pad);i+=3,j+=4) {
        dest[j]     = B64Table[(                             ((src[i]   & 0xFC) >> 2) )];
        dest[j+1]   = B64Table[( ((src[i]   << 4) & 0x30)  | ((src[i+1] & 0xF0) >> 4) )];

        dest[j+2]   = B64Table[( ((src[i+1] << 2) & 0x3C)  | ((src[i+2] & 0xC0) >> 6) )];
        dest[j+3]   = B64Table[(                             ((src[i+2] & 0x3F)     ) )];
      }
    //Process the Padded Tail, if Needed . . .
      if (pad>0) {
        //Given
          dest[j]   = B64Table[(                             ((src[i]   & 0xFC) >> 2) )];
        if (pad>1) {
          dest[j+1] = B64Table[( ((src[i]   << 4) & 0x30)  | ((src[i+1] & 0xF0) >> 4) )];
          dest[j+2] = B64Table[( ((src[i+1] << 2) & 0x3C)  | ((src[i+2] & 0xC0) >> 6) )];
        } else {
          dest[j+1] = B64Table[( ((src[i]   << 4) & 0x30)                             )];
          dest[j+2] = B64Table[64]; // "="
        }
        //Given
          dest[j+3] = B64Table[64]; // "="
      } // end if (pad>0)

    // Debugging
    // printf("Encoded [%d] Base64 Bytes from [%d] Original Bytes.\n",ret,size); //debugging


    return ret;
  } // end function
  //--------------------------------------------------------------------------------------------
  int base64_decode(char *in, void *out) {
    int size = strspn(in,B64Table);
    int i,j,x; // indexes into Src and Dest
    int pad = 0;
    int in1,in2,in3,in4;
    int numWholeQuantums;
    int numOutputBytes;
    char* dest;

    while (in[(size-1)-pad] == B64Table[64]) { pad++; } // count padding bytes...

    numWholeQuantums = (size-pad)/4;
    numOutputBytes   = (numWholeQuantums * 3);
    if (pad) {
      size -= 4; // Remove last Quantum from main processing loop.
      numOutputBytes+=1;
      if (pad<2) numOutputBytes++;
    }

    //Allocate a suitable buffer, if requested . . .
      if (!out) {
        out = dest = (char*)malloc(numOutputBytes + 1);
      } else {
        dest = (char*)out;
      }

    //Process the Non-Padded Quantums . . .
      for (x=0,i=0,j=0; x<numWholeQuantums; x++,i+=4,j+=3) {
          in1=Un64(in[i]); in2=Un64(in[i+1]); in3=Un64(in[i+2]); in4=Un64(in[i+3]);
          dest[j]   = ((in1 << 2) & 0xFC) | ((in2 >> 4) & 0x03);
          dest[j+1] = ((in2 << 4) & 0xF0) | ((in3 >> 2) & 0x0F);
          dest[j+2] = ((in3 & 0x03) << 6) | (in4);
          // Debugging
          // printf("Quantum [%3d] of [%3d] Yield:  [%c][%c][%c]\n",x,numWholeQuantums,dest[j],dest[j+1],dest[j+2]);
      }

    //Process the Padded Tail, if Needed . . .
      if (pad) {
          in1=Un64(in[i]); in2=Un64(in[i+1]); in3=Un64(in[i+2]); in4=Un64(in[i+3]);
          dest[j]   = ((in1 << 2) & 0xFC) | ((in2 >> 4) & 0x03);
        if (in3 >=0) {
          dest[j+1] = ((in2 << 4) & 0xF0) | ((in3 >> 2) & 0x0F);
          dest[j+2] = ((in3 << 6) & 0xC0);
        } else {
          dest[j+1] = ((in2 << 4) & 0xF0);
        }
        // Debugging
        // printf("Quantum [PAD] of [%3d] Yield:  [%c][%c][%c]\n",numWholeQuantums,dest[j],dest[j+1],dest[j+2]);
      }
    return numOutputBytes;
  }
  //--------------------------------------------------------------------------------------------
