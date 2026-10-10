#ifndef __PATTERN_H
#define __PATTERN_H

/* 关键字最大支持128个字节 */
#define PATTERN_SIZE_MAX 128
#define NAME_LEN 32
#define EXTRA_DATA_LEN 32

typedef struct pattern_s
{
    uint16_t pattern_len;
    int16_t  offset;
    uint16_t depth;
    char __end[0];
    uint32_t repeated:1,
        action:4,
        nocase:1,
        match_full_path:1,
        type:2, //0:self_protecct, 1:lesou_protection,2:tamper_protection
        isnot_extend:1,
        rid:16;
    uint16_t id;
    unsigned char pattern[PATTERN_SIZE_MAX];
    unsigned char name[NAME_LEN];
    char extra_data[EXTRA_DATA_LEN];

}pattern_t;



enum PATTERN_ACTION {
    PASS_RETURN,
    BLOCK_RETURN,
    CONTINUE_RUN,
    SELF_PROTECTION,
    TRUSTDIR_ACTION
};

enum PATTERN_TYPE {
    SELF_PROTECTION_TYPE,
    LESOU_PROTECTION_TYPE,
    TAMPER_PROTECTION_TYPE
};


#endif
