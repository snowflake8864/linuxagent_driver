#include <linux/types.h>
#include <linux/slab.h>
#include "gnHead.h"
#include "core/kvd_core.h"

u_char* tlv_packet_make(u_char pt,u_char* data,
        u_short data_len,u_short* pack_len)
{
    u_char* tlv_data = NULL;
    u_short len = data_len + TLV_HDR_LEN;

    tlv_data = kzalloc(len,GFP_ATOMIC);
    if(!tlv_data) { return ERR_PTR(-ENOMEM); }

    tlv_data[0] = pt;
    memcpy(tlv_data + 1,&data_len,sizeof(data_len));
    memcpy(tlv_data + TLV_HDR_LEN,data,data_len);
    *pack_len = len;
    
    return tlv_data;
}

void tlv_packet_free(u_char* packet)
{
    if(!KVD_IS_ERR_OR_NULL(packet)) {
        kfree(packet);
    }
}

u_short tlv_fill_int(u_char vt,char* data,u_int nval)
{
    u_short len = 0;

    data[len++] = vt & 0xFF;
    *((u_short*)(data + len)) = sizeof(u_int) & 0xFFFF;
    len += sizeof(u_short);
    *((u_int*)(data + len)) = nval;
    len += sizeof(u_int);

    return len;
}

u_short tlv_fill_int64(u_char vt,char* data,uint64_t nval)
{
    u_short len = 0;

    data[len++] = vt & 0xFF;
    *((u_short*)(data + len)) = sizeof(uint64_t) & 0xFFFF;
    len += sizeof(u_short);
    *((uint64_t*)(data + len)) = nval;
    len += sizeof(uint64_t);

    return len;
}

u_short tlv_fill_str(u_char vt,char* data,
            const char* sval,unsigned slen)
{
    u_short len = 0;

    data[len++] = vt & 0xFF;
    *((u_short*)(data + len)) = slen & 0xFFFF;
    len += sizeof(u_short);
    memcpy(data + len,sval,slen);
    len += slen;

    return len;
}

u_short tlv_fill_ushort(u_char vt,char* data,u_short nval)
{
    u_short len = 0;

    data[len++] = vt & 0xFF;
    *((u_short*)(data + len)) = sizeof(u_short) & 0xFFFF;
    len += sizeof(u_short);
    *((u_short*)(data + len)) = nval;
    len += sizeof(u_short);

    return len;
}

u_short tlv_fill_uchar(u_char vt,char* data,u_char val)
{
    u_short len = 0;

    data[len++] = vt & 0xFF;
    *((u_short*)(data + len)) = sizeof(u_char) & 0xFFFF;
    len += sizeof(u_short);
    *((u_char*)(data + len)) = val;
    len += sizeof(u_char);

    return len;
}

int tlv_data_parse(u_char* data,u_short data_len,void* ctx,
            void (*cb)(u_char vt,u_short len,u_char* value,void* ctx))
{
    int rc = 0;
    u_short i = 0;
    u_char* p = data;

    for(;i < data_len;p = data + i) {
        u_short len = 0;
        u_char vt = p[0];
        u_char* value = NULL;
        
        if((i + TLV_HDR_LEN) >= data_len) {
            rc = -EINVAL;
            break;
        }
        
        memcpy(&len,p + 1,sizeof(len));
        i += (TLV_HDR_LEN + len);
        //一定要检验一下，保证value指向的内在是有效的
        if(i > data_len) {
            rc = -EINVAL;
            break; 
        }

        value = p + TLV_HDR_LEN;
        cb(vt,len,value,ctx);
    }

    return rc;
}

