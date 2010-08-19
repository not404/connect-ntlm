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
int base64_encode(void *data, int size, char** dest);
int base64_decode(char *data, void *dest);
