#ifndef KOSEC_DEFENSE_LSM_H
#define KOSEC_DEFENSE_LSM_H

int defense_lsm_init(void);
void defense_lsm_uninit(void);

void defense_hook_lsm_ops(void);
void defense_cleanup_lsm_ops(void);
#endif
