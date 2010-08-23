static:
	gcc connect.c ne_ntlm.c base64.c des.c -o connect-ntlm

# TODO:  this won't work without porting MD4
# static-full-ntlm:
#	gcc -DUSE_NTRESPONSES connect.c ne_ntlm.c base64.c des.c -o connect-ntlm

dynamic:
	gcc  -DUSE_SSLEAY connect.c ne_ntlm.c base64.c -o connect-ntlm -lcrypto

dynamic-full-ntlm:
	gcc  -DUSE_SSLEAY -DUSE_NTRESPONSES connect.c ne_ntlm.c base64.c -o connect-ntlm -lcrypto


## Internal Use - probably only useful to a developer ##
static-debug:
	gcc -DLALEE_DEBUG connect.c ne_ntlm.c base64.c des.c -o connect-ntlm

dynamic-debug:
	gcc -DLALEE_DEBUG -DUSE_SSLEAY connect.c ne_ntlm.c base64.c -o connect-ntlm -lcrypto

