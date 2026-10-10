#include <linux/types.h>
#include "gnHead.h"
#include "core/gnkernel.h"
#include "defense_inner.h"
#include "utils/utils.h"

typedef struct  {
    u_char op;
    u_char cnt;
    u_int pids[128];
}pid_policy_ctx_t;

typedef struct {
    u_char op;
    char *paths[64];
    u_short paths_len[64];
    u_char cnt;
} file_policy_ctx_t;

static void file_policy(u_char vt, u_short len, u_char *value, void *ctx)
{
    int copy_len = 0;
    char *tmp_path = NULL;
    file_policy_ctx_t *pctx = ctx;

    BUG_ON(((vt != TLV_VT_PATH) && (vt != TLV_VT_OP)) || (value == NULL));

    if (vt == TLV_VT_OP) {
        pctx->op = *value;
    } else {
        if (pctx->op == DEFENSE_OP_CLEAN) {
            // 如果是清空路径，则忽略后面跟随的路径信息，反正也不用，省的到时候还需释放空间。
            return;
        }
        if (pctx->cnt < ARRAY_SIZE(pctx->paths)) {
            tmp_path = __getname();
            if (tmp_path == NULL) {
                return;
            }
            memset(tmp_path, 0, PATH_MAX);
            copy_len = len > PATH_MAX ? PATH_MAX : len;
            pctx->paths[pctx->cnt] = tmp_path;
            pctx->paths_len[pctx->cnt] = (u_short)copy_len;
            memcpy(pctx->paths[pctx->cnt], value, copy_len);
            pctx->cnt++;
        }
    }
}

extern int defense_add_del_path(char *path, size_t len, bool b_add);
extern int defense_clean_path(void);

static void defense_files_policy(void *data, size_t data_len)
{
    u_short i;
    bool b_add;
    file_policy_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    tlv_data_parse(data, data_len, &ctx, file_policy);

    if (ctx.op == DEFENSE_OP_CLEAN) {
        defense_clean_path();
    } else {
        b_add = (ctx.op == DEFENSE_OP_UPGRADE);
        for (i = 0; i < ctx.cnt; ++i) {
            if (ctx.paths[i] == NULL) {
                continue;
            }
            defense_add_del_path(ctx.paths[i], (size_t)ctx.paths_len[i], b_add);
            __putname(ctx.paths[i]);
        }
    }
}

static tlv_proto_fn_t tlv_handlers[] = {
        [DEFENSE_CMD_PIDS] = defense_pids_policy,
        [DEFENSE_CMD_FILES] = defense_files_policy,
    };

static void defense_tlv_policy(void* data,size_t data_len)
{
    u_char cmd = 0;
    u_short len = 0;
    u_char* tlv_data = data;

    if(!data || data_len < TLV_HDR_LEN) {
        return;
    }

    cmd = tlv_data[0];
    len = *((u_short*)(tlv_data + 1));

    if(cmd >= ARRAY_SIZE(tlv_handlers)) {
        return;
    }

    if(len != (data_len - TLV_HDR_LEN)) {
        DEFENSE_LOG_ERROR("bad defense tlv data_len,we expect %u,"
            "but received: %lu\n",len,data_len - TLV_HDR_LEN);
        return;
    }

    if(tlv_handlers[cmd] == NULL) {
        DEFENSE_LOG_ERROR("bad defense tlv cmd: %u,no handler\n",
            cmd & 0xFF);
        return;
    }

    tlv_handlers[cmd](tlv_data + TLV_HDR_LEN,len);
}

static vsec_tlv_proto_cb_t defense_tlv_cb = 
    {
        .pt = OSEC_PT_SELF,
        .pfunc = defense_tlv_policy,
    };

int defense_tlv_proto_init(void)
{
    int rc = 0;
    rc = register_tlv_proto_callback(&defense_tlv_cb);
    if(rc) {
        DEFENSE_LOG_ERROR("register ad tlv-proto failed,rc: %d\n",rc);
    }

    return rc;
}

void defense_tlv_proto_uninit(void)
{
    unregister_tlv_proto_callback(&defense_tlv_cb);
}
