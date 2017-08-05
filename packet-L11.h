#ifndef L11 
#define L11


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdio.h>
#include <epan/value_string.h>
typedef struct {
    guint encoding;
    guint segment_number;
    guint number_of_segments;
	char segments[10000];
	int taille;
	int subtype;
	int stn;
}L11State;
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* simple.h */