#include "cJSON.h"
#include "js_util.h"

int vsec_json_get_int(int* nval,cJSON* parent,
                    const char* name)
{
    int rc = -EINVAL;
    cJSON* js_sub = NULL;
    
    //Note:由于只针对报文处理，
    //如果此处对应字段不存在，我们直接返回BADMSG
    js_sub = cJSON_GetObjectItem(parent,name);
    if(!cJSON_IsNumber(js_sub)) {
        return rc;
    }

    rc = 0;
    *nval = js_sub->valueint;
    return rc;
}

const char* vsec_json_get_str(cJSON* parent,
                        const char* name)
{
    char* str = NULL;
    cJSON* js_sub = NULL;
    
    //Note:由于只针对报文处理，
    //如果此处对应字段不存在，我们直接返回BADMSG
    js_sub = cJSON_GetObjectItem(parent,name);
    if(!cJSON_IsString(js_sub)) {
        return str;
    }

    str = cJSON_GetStringValue(js_sub);
    return str;
}
