#ifndef __PROCESS_DPI_PATTERN_TBL_H__
#define __PROCESS_DPI_PATTERN_TBL_H__
#define PATTERN_SIZE_MAX 128
#define NAME_LEN 32
#define EXTRA_DATA_LEN 32
#include <linux/types.h>
#define PROCESS_DPI_STATE_TBL_MAX 512
#define PROCESS_DPI_PATTERN_MAX 128

typedef struct process_pattern_s
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
        type:4; //0:self_protecct, 1:lesou_protection,2:tamper_protection
    int16_t pkt_len;
    uint16_t id;
    unsigned char pattern[PROCESS_DPI_PATTERN_MAX];
    unsigned char name[NAME_LEN];

}process_pattern_t;

struct process_pattern_list
{   
    uint16_t nextstate_id;
};  
    
struct process_state_array
{
    struct process_pattern_list pattern[PROCESS_DPI_PATTERN_MAX];
    uint32_t type_id;
    //uint8_t enable;
};
typedef struct {
    uint8_t type[5];
    uint8_t action[5];
    int16_t rule_idx[5];
	uint16_t opt;
    uint8_t cnt:4;
}process_dpi_result_t;


extern struct process_state_array *Process_DPI_State_TBL;
extern int *Process_DPI_State_Flag_TBL;
extern uint16_t Process_G_state_id_inc;


int process_pattern_init(struct proc_dir_entry *proc_parent); 
void process_pattern_exit(struct proc_dir_entry *proc_parent); 
process_pattern_t *get_process_pattern_by_name(const char * name);
int process_acsmSearch3(const char *str, int str_len, process_dpi_result_t *result);
#endif
