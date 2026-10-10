#ifndef KOSEC_JS_UTIL_H
#define KOSEC_JS_UTIL_H

struct cJSON;

int vsec_json_get_int(int* nval,cJSON* parent,
                    const char* name);
const char* vsec_json_get_str(cJSON* parent,
                        const char* name);

#endif
