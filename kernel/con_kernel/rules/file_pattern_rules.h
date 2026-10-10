#ifndef __FILE_PATTERN_RULES_H
#define __FILE_PATTERN_RULES_H
#include "pattern.h"

int file_pattern_init(struct proc_dir_entry *proc_parent);
void file_pattern_exit(struct proc_dir_entry *proc_parent);
int file_acsmSearch(const char *str, int str_len);

#endif
