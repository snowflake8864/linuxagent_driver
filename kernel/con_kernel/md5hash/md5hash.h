#ifndef __MD5HASH_MD5HASH_H__
#define __MD5HASH_MD5HASH_H__


int  md5_module_init(void);
void  md5_module_exit(void);
int md5_calculate_file(const char *filename, char *digest);

#endif
