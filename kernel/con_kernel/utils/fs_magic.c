#include <linux/module.h>
#include "fs_magic.h"

//一定要要关注的文件系统类型，即要扫描的
static uint64_t care_fs[] = {
    EXT_SUPER_MAGIC,//ext2,ext3,ext4文件系统类型标识都是一样的
    XFS_SB_MAGIC,//xfs
    MSDOS_SUPER_MAGIC,//msdos: fat,fat32
    BTRFS_SUPER_MAGIC,//btrfs
    NTFS_SB_MAGIC,//ntfs
    REISERFS_SUPER_MAGIC,//reiserfs
};

//无需扫描，需要跳过的文件系统
static uint64_t skip_fs[] = {
    PROC_SUPER_MAGIC,//proc fs
    SYSFS_MAGIC,//sys fs
    DEBUGFS_MAGIC,//debug fs
    PIPEFS_MAGIC,//pipe fs
    SELINUX_MAGIC,//selinux fs
    SECURITYFS_MAGIC, //seucrity fs
    DEVPTS_SUPER_MAGIC,//devpts fs
    USBDEVICE_SUPER_MAGIC,//usb fs
    SMACK_MAGIC,//smack fs
    SOCKFS_MAGIC,//sock fs
    ECRYPTFS_SUPER_MAGIC,//encrypt fs
    HUGETLBFS_MAGIC,//hugeLB fs
    SQUASHFS_MAGIC,
    MTD_INODE_FS_MAGIC,//MTD fs
    ANON_INODE_FS_MAGIC,//anonymous fs
    BTRFS_TEST_MAGIC,//btrfs test
    BINFMTFS_MAGIC,//binfmts fs
    NSFS_MAGIC, //nsfs,it's just readonly
    BPF_FS_MAGIC,//bpf
};

int vsec_is_care_fs(uint64_t fs_type)
{
    int ok = 0;
    size_t i = 0;
    size_t size = 0;
    size = sizeof(care_fs) /
           sizeof(care_fs[0]);
    for(i = 0;!ok && (i < size);i++) {
        ok = (care_fs[i] == fs_type);
    }

    return ok;
}

int vsec_is_skip_fs(uint64_t fs_type)
{
    int ok = 0;
    size_t i = 0;
    size_t size = 0;
    size = ARRAY_SIZE(skip_fs);
    for(i = 0;!ok && (i < size);i++) {
        ok = (skip_fs[i] == fs_type);
    }

    return ok;
}

//网络文件系统
static uint64_t net_fs[] = {
    NFS_SUPER_MAGIC,
    SMB_SUPER_MAGIC,
    CIFS_MAGIC_NUMBER,
};

int vsec_is_net_fs(uint64_t fs_type)
{
    int ok = 0;
    size_t i = 0;
    size_t size = 0;
    size = ARRAY_SIZE(net_fs);
    for(i = 0;!ok && (i < size);i++) {
        ok = (net_fs[i] == fs_type);
    }

    return ok;
}


const char* vsec_str_fs_type(uint64_t fs_type)
{
    const char* str = "unkownfs";
    switch(fs_type) {
        case ADFS_SUPER_MAGIC:
            str = "adfs";
        break;
        case AFFS_SUPER_MAGIC:
            str = "affs";
        break;
        case AFS_SUPER_MAGIC:
            str = "afs";
        break;
        case AUTOFS_SUPER_MAGIC:
            str = "autofs";
        break;
        case CODA_SUPER_MAGIC:
            str = "codafs";
        break;
        case CRAMFS_MAGIC:
            str = "cramfs";
        break;
        case DEBUGFS_MAGIC:
            str = "debugfs";
        break;
        case SECURITYFS_MAGIC:
            str = "securityfs";
        break;
        case SELINUX_MAGIC:
            str = "selinuxfs";
        break;
        case SMACK_MAGIC:
            str = "smackfs";
        break;
        case RAMFS_MAGIC:
            str = "ramfs";
        break;
        case TMPFS_MAGIC:
            str = "tmpfs";
        break;
        case HUGETLBFS_MAGIC:
            str = "hugetlbfs";
        break;
        case SQUASHFS_MAGIC:
            str = "squashfs";
        break;
        case ECRYPTFS_SUPER_MAGIC:
            str = "ecryptfs";
        break;
        case EFS_SUPER_MAGIC:
            str = "efs";
        break;
        //ext2,ext3,ext4文件系统　三者标识一样
        //在应用层直接认为是extfs即可
        case EXT_SUPER_MAGIC:
            str = "extfs";
        break;
        case XENFS_SUPER_MAGIC:
            str = "xenfs";
        break;
        case BTRFS_SUPER_MAGIC:
            str = "btrfs";
        break;
        case NILFS_SUPER_MAGIC:
            str = "nilfs";
        break;
        case F2FS_SUPER_MAGIC:
            str = "f2fs";
        break;
        case HPFS_SUPER_MAGIC:
            str = "hpfs";
        break;
        case ISOFS_SUPER_MAGIC:
            str = "isofs";
        break;
        case JFFS2_SUPER_MAGIC:
            str = "jffs2";
        break;
        case PSTOREFS_MAGIC:
            str = "pstorefs";
        break;
        case EFIVARFS_MAGIC:
            str = "efivarfs";
        break;
        case HOSTFS_SUPER_MAGIC:
            str = "hostfs";
        break;
        case MINIX_SUPER_MAGIC:		/* minix v1 fs, 14 char names */
            str = "minixfs14";
        break;
        case MINIX_SUPER_MAGIC2:		/* minix v1 fs, 30 char names */
            str = "minixfs30";
        break;
        case MINIX2_SUPER_MAGIC:	/* minix v2 fs, 14 char names */
            str = "minix2fs14";
        break;
        case MINIX2_SUPER_MAGIC2:	/* minix v2 fs, 30 char names */
            str = "minix2fs20";
        break;
        case MINIX3_SUPER_MAGIC:		/* minix v3 fs, 60 char names */
            str = "minix3fs";
        break;

        case MSDOS_SUPER_MAGIC:	/* MD */
            str = "msdosfs";
        break;
        case NFS_SUPER_MAGIC:
            str = "nfs";
        break;
        case OPENPROM_SUPER_MAGIC:
            str = "openpromfs";
        break;
        case QNX4_SUPER_MAGIC: /* qnx4 fs detection */
            str = "qnx4fs";
        break;
        case QNX6_SUPER_MAGIC:	/* qnx6 fs detection */
            str = "qnx6fs";
        break;
        case REISERFS_SUPER_MAGIC:	/* used by gcc */
            str = "reiserfs";
        break;
        case SMB_SUPER_MAGIC:
            str = "smbfs";
        break;
        case CGROUP_SUPER_MAGIC:
            str = "cgroupfs";
        break;
        case V9FS_MAGIC:
            str = "v9fs";
        break;
        case BDEVFS_MAGIC:
            str = "bdevfs";
        break;
        case BINFMTFS_MAGIC:
            str = "binfmtfs";
        break;
        case DEVPTS_SUPER_MAGIC:
            str = "devptsfs";
        break;
        case FUTEXFS_SUPER_MAGIC:
            str = "futexfs";
        break;
        case XFS_SB_MAGIC:
            str = "xfs";
        break;
        case PIPEFS_MAGIC:
            str = "pipefs";
        break;
        case PROC_SUPER_MAGIC:
            str = "procfs";
        break;
        case SOCKFS_MAGIC:
            str = "sockfs";
        break;
        case SYSFS_MAGIC:
            str = "sysfs";
        break;
        case USBDEVICE_SUPER_MAGIC:
            str = "usbdevicefs";
        break;
        case MTD_INODE_FS_MAGIC:
            str = "mtdfs";
        break;
        case ANON_INODE_FS_MAGIC:
            str = "anonfs";
        break;
        case BTRFS_TEST_MAGIC:
            str = "btrfstest";
        break;
        case NSFS_MAGIC:
            str = "nsfs";
        break;
        case BPF_FS_MAGIC:
            str = "bpf";
        break;
        default:
        break;
    }

    return str;
}

