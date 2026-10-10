#ifndef __PROCESS_PATTERN_RULES_H
#define __PROCESS_PATTERN_RULES_H

#include "pattern.h"
int process_pattern_init(struct proc_dir_entry *proc_parent);
void process_pattern_exit(struct proc_dir_entry *proc_parent);
int process_acsmSearch(const char *str, int str_len);

#endif
