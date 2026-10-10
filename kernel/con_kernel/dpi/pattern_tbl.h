#ifndef __DPI_PATTERN_TBL_H__
#define __DPI_PATTERN_TBL_H__
/* 关键字最大支持128个字节 */
#define PATTERN_SIZE_MAX 128
#define NAME_LEN 32
#define EXTRA_DATA_LEN 32
#include <linux/types.h>
#define DPI_STATE_TBL_MAX 512
#define DPI_PATTERN_MAX 128
enum PATTERN_TYPE {
    SELF_PROTECTION_TYPE,
    LESOU_PROTECTION_TYPE,
    TAMPER_PROTECTION_TYPE
};


typedef struct pattern_s
{
    uint16_t pattern_len;
    int16_t  offset;
    uint16_t depth;
    char __end[0];
    uint32_t repeated:1,
        action:4,
        nocase:1,
        case_offset:1,
        first:1,
        match_full_path:1,
        isnot_extend:1,
        type:2, //0:self_protecct, 1:lesou_protection,2:tamper_protection
		is_file:2;
    int16_t pkt_len;
    uint16_t id;
    unsigned char pattern[DPI_PATTERN_MAX];
    unsigned char name[NAME_LEN];

}pattern_t;

struct pattern_list
{   
    uint16_t nextstate_id;
};  
    
struct state_array
{
    struct pattern_list pattern[DPI_PATTERN_MAX];
    uint32_t type_id;
    //uint8_t enable;
};
typedef struct {
    uint8_t type[5];
    uint8_t action[5];
    int16_t rule_idx[5];
    uint8_t protect_rw[5];
    uint8_t is_file[5];
    int8_t tpnc[5];
	uint16_t is_dir:9,
             is_cut_kpathname:1,
             opt:6;
    uint8_t cnt:4;
}dpi_result_t;


extern struct state_array *DPI_State_TBL;
extern int *DPI_State_Flag_TBL;
extern uint16_t G_state_id_inc;


int pattern_init(struct proc_dir_entry *proc_parent); 
void pattern_exit(struct proc_dir_entry *proc_parent); 
pattern_t *get_pattern_by_name(const char * name);
int file_acsmSearch3(const char *str, int str_len, dpi_result_t *result);
#endif
