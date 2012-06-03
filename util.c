#include <string.h>
#include <strings.h>
#include "util.h"
#include <math.h>
int hex_to_int(const char ,int );
void eth_addr_parse(const char *s,char *d) {
	int idx = 0;
	int beg = 0;
	int li = 0;
	char *ptr = NULL;
	size_t s_len = strlen(s);
	while(beg <= s_len && (ptr = index(s+beg, (int)'-')) != NULL) {
		char sub[64] = {0};
		int sum = 0;
		int i = 1, j = 0;
		idx = ptr - s;
		memcpy(sub, s + beg, idx - beg);
		for(j = strlen(sub); j > 0;j--){
			sum += hex_to_int(sub[j - 1],i++);
		}
		d[li++] = sum;
		beg = idx + 1;
	}
	if(beg < s_len) {
		char sub[64] = {0};
		int sum = 0;
		int i = 1, j = 0;
		memcpy(sub, s + beg, s_len - beg);
		for(j = strlen(sub); j > 0;j--) {
			sum += hex_to_int(sub[j - 1],i++);
		}
		d[li++] = sum;
	}
}

int hex_to_int(const char c,int i) { 
	int j;
	for(j = 0; j < 6; j++) {

		if(c == (char)(97+j)) {
			return (10 + c - 97)*(int)pow(16,i-1);
		}
	}
	char buf[1] ;
	buf[0] = c;
	return atoi(buf)*(int)pow(16,i-1);
}

