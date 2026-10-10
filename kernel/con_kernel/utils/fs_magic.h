#ifndef __FS_MAGIC_H__
#define __FS_MAGIC_H__

#include <linux/types.h>

#ifndef ADFS_SUPER_MAGIC
#define ADFS_SUPER_MAGIC	0xadf5
#endif

#ifndef AFFS_SUPER_MAGIC
#define AFFS_SUPER_MAGIC	0xadff
#endif

#ifndef AFS_SUPER_MAGIC
#define AFS_SUPER_MAGIC                0x5346414F
#endif

#ifndef AUTOFS_SUPER_MAGIC
#define AUTOFS_SUPER_MAGIC	0x0187
#endif

#ifndef CODA_SUPER_MAGIC
#define CODA_SUPER_MAGIC	0x73757245
#endif

#ifndef CRAMFS_MAGIC
#define CRAMFS_MAGIC		0x28cd3d45	/* some random number */
#endif

#ifndef CRAMFS_MAGIC_WEND
#define CRAMFS_MAGIC_WEND	0x453dcd28	/* magic number with the wrong endianess */
#endif

#ifndef DEBUGFS_MAGIC
#define DEBUGFS_MAGIC          0x64626720
#endif

#ifndef SECURITYFS_MAGIC
#define SECURITYFS_MAGIC	0x73636673
#endif

#ifndef SELINUX_MAGIC
#define SELINUX_MAGIC		0xf97cff8c
#endif

#ifndef SMACK_MAGIC
#define SMACK_MAGIC		0x43415d53	/* "SMAC" */
#endif

#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC		0x858458f6	/* some random number */
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC		0x01021994
#endif

#ifndef HUGETLBFS_MAGIC
#define HUGETLBFS_MAGIC 	0x958458f6	/* some random number */
#endif

#ifndef SQUASHFS_MAGIC
#define SQUASHFS_MAGIC		0x73717368
#endif

#ifndef ECRYPTFS_SUPER_MAGIC
#define ECRYPTFS_SUPER_MAGIC	0xf15f
#endif

#ifndef EFS_SUPER_MAGIC
#define EFS_SUPER_MAGIC		0x414A53
#endif

#ifndef EXT2_SUPER_MAGIC
#define EXT2_SUPER_MAGIC	0xEF53
#endif

#ifndef EXT3_SUPER_MAGIC
#define EXT3_SUPER_MAGIC	0xEF53
#endif

#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC	0xEF53
#endif

//ext2,ext3,ext4文件系统的标识都是相同的
//所以我们再定义一个宏，这个宏在linux内核中实际是没有的
#ifndef EXT_SUPER_MAGIC
#define EXT_SUPER_MAGIC	0xEF53
#endif

#ifndef XENFS_SUPER_MAGIC
#define XENFS_SUPER_MAGIC	0xabba1974
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC	0x9123683E
#endif

#ifndef NILFS_SUPER_MAGIC
#define NILFS_SUPER_MAGIC	0x3434
#endif

#ifndef F2FS_SUPER_MAGIC
#define F2FS_SUPER_MAGIC	0xF2F52010
#endif

#ifndef HPFS_SUPER_MAGIC
#define HPFS_SUPER_MAGIC	0xf995e849
#endif

#ifndef ISOFS_SUPER_MAGIC
#define ISOFS_SUPER_MAGIC	0x9660
#endif

#ifndef JFFS2_SUPER_MAGIC
#define JFFS2_SUPER_MAGIC	0x72b6
#endif

#ifndef PSTOREFS_MAGIC
#define PSTOREFS_MAGIC		0x6165676C
#endif

#ifndef EFIVARFS_MAGIC
#define EFIVARFS_MAGIC		0xde5e81e4
#endif

#ifndef HOSTFS_SUPER_MAGIC
#define HOSTFS_SUPER_MAGIC	0x00c0ffee
#endif

#ifndef MINIX_SUPER_MAGIC
#define MINIX_SUPER_MAGIC	0x137F		/* minix v1 fs, 14 char names */
#endif

#ifndef MINIX2_SUPER_MAGIC2
#define MINIX_SUPER_MAGIC2	0x138F		/* minix v1 fs, 30 char names */
#endif


#ifndef MINIX2_SUPER_MAGIC
#define MINIX2_SUPER_MAGIC	0x2468		/* minix v2 fs, 14 char names */
#endif

#ifndef MINIX2_SUPER_MAGIC2
#define MINIX2_SUPER_MAGIC2	0x2478		/* minix v2 fs, 30 char names */
#endif

#ifndef MINIX3_SUPER_MAGIC
#define MINIX3_SUPER_MAGIC	0x4d5a		/* minix v3 fs, 60 char names */
#endif

#ifndef MSDOS_SUPER_MAGIC
#define MSDOS_SUPER_MAGIC	0x4d44		/* MD */
#endif

#ifndef NCP_SUPER_MAGIC
#define NCP_SUPER_MAGIC		0x564c		/* Guess, what 0x564c is :-) */
#endif

#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC		0x6969
#endif

#ifndef CIFS_MAGIC_NUMBER
#define CIFS_MAGIC_NUMBER 0xFF534D42
#endif

#ifndef OPENPROM_SUPER_MAGIC
#define OPENPROM_SUPER_MAGIC	0x9fa1
#endif

#ifndef QNX4_SUPER_MAGIC
#define QNX4_SUPER_MAGIC	0x002f		/* qnx4 fs detection */
#endif

#ifndef QNX6_SUPER_MAGIC
#define QNX6_SUPER_MAGIC	0x68191122	/* qnx6 fs detection */
#endif


#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC	0x52654973	/* used by gcc */
#endif
					/* used by file system utilities that
	                                   look at the superblock, etc.  */

#ifndef SMB_SUPER_MAGIC
#define SMB_SUPER_MAGIC		0x517B
#endif

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC	0x27e0eb
#endif


#ifndef STACK_END_MAGIC
#define STACK_END_MAGIC		0x57AC6E9D
#endif

#ifndef V9FS_MAGIC
#define V9FS_MAGIC		0x01021997
#endif

#ifndef BDEVFS_MAGIC
#define BDEVFS_MAGIC            0x62646576
#endif

#ifndef BINFMTFS_MAGIC
#define BINFMTFS_MAGIC          0x42494e4d
#endif

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC	0x1cd1
#endif

#ifndef FUTEXFS_SUPER_MAGIC
#define FUTEXFS_SUPER_MAGIC	0xBAD1DEA
#endif

#ifndef XFS_SB_MAGIC
#define	XFS_SB_MAGIC		0x58465342
#endif

#ifndef PIPEFS_MAGIC
#define PIPEFS_MAGIC            0x50495045
#endif

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC	0x9fa0
#endif

#ifndef SOCKFS_MAGIC
#define SOCKFS_MAGIC		0x534F434B
#endif

#ifndef SYSFS_MAGIC
#define SYSFS_MAGIC		0x62656572
#endif

#ifndef USBDEVICE_SUPER_MAGIC
#define USBDEVICE_SUPER_MAGIC	0x9fa2
#endif

#ifndef MTD_INODE_FS_MAGIC
#define MTD_INODE_FS_MAGIC      0x11307854
#endif

#ifndef ANON_INODE_FS_MAGIC
#define ANON_INODE_FS_MAGIC	0x09041934
#endif

#ifndef BTRFS_TEST_MAGIC
#define BTRFS_TEST_MAGIC	0x73727279
#endif

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

#ifndef NTFS_SB_MAGIC
#define NTFS_SB_MAGIC 0x5346544e	/* 'NTFS' */
#endif

#ifndef NSFS_MAGIC
#define NSFS_MAGIC  0x6e736673
#endif

#ifndef  BPF_FS_MAGIC
#define BPF_FS_MAGIC	0xcafe4a11
#endif

int vsec_is_net_fs(uint64_t fs_type);
int vsec_is_care_fs(uint64_t fs_type);
int vsec_is_skip_fs(uint64_t fs_type);
const char* vsec_str_fs_type(uint64_t fs_type);

#endif /* __FS_MAGIC_H__ */
