#ifndef DIS_SIMPLE 
#define DIS_SIMPLE


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
} DISState;
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* simple.h */