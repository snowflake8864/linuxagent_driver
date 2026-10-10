/*
 *zcopy.h: 2023-08-02 created by zebra
 */
#ifndef _ZCOPY_H
#define _ZCOPY_H
#define IN_NETLOG_AUDIT_ENABLE  (1)
#define OUT_NETLOG_AUDIT_ENABLE  (1<<1)
#define OPENPORT_AUDIT_ENABLE  (1<<2)
#define DNS_NETLOG_AUDIT_ENABLE  (1<<3)
#define PROCESS_AUDIT_ENABLE  (1<<4)
#define FILE_AUDIT_ENABLE  (1<<5)
extern int zero_copy_load_succeed;
extern int in_netlog_audit_data_count;
extern int out_netlog_audit_data_count;
extern int openport_audit_data_count;
extern int dns_netlog_audit_data_count;
extern int process_audit_data_count;
extern int file_audit_data_count;
int  zcopy_init(const struct proc_dir_entry *base_proc);
void zcopy_exit(const struct proc_dir_entry *base_proc);
//int get_file_audit_data(struct av_file_info ** info);
uint32_t get_in_netlog_audit_data(struct osec_network_report ** info);
uint32_t get_in_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx);
uint32_t get_out_netlog_audit_data(struct osec_network_report ** info);
uint32_t get_out_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx);
uint32_t get_openport_audit_data(struct osec_openport_report ** info);
uint32_t get_openport_audit_idx(uint32_t *prev_idx, uint32_t *idx);
uint32_t get_dns_netlog_audit_data(struct osec_dns_report ** info);
uint32_t get_dns_netlog_audit_idx(uint32_t *prev_idx, uint32_t *idx);
uint32_t get_process_audit_data(struct av_process_info ** info);
uint32_t get_process_audit_idx(uint32_t *prev_idx, uint32_t *idx);
uint32_t get_file_audit_data(struct av_file_info ** info);
uint32_t get_file_audit_idx(uint32_t *prev_idx, uint32_t *idx);
#endif

