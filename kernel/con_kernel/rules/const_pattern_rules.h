#ifndef __CONST_PATTERN_RULES_H
#define __CONST_PATTERN_RULES_H

int const_pattern_init(struct proc_dir_entry *proc_parent);
void const_pattern_exit(struct proc_dir_entry *proc_parent);
int const_acsmSearch(const char *str, int str_len);

#endif
