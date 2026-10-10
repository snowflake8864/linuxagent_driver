#ifndef CORE_TLV_ATTR
#define CORE_TLV_ATTR

#include <linux/types.h>

struct tlv_attr {
    u8 type;
    u16 len;
} __attribute__((packed));

struct tlva_policy {
    u16 type;
    u16 len;
};

enum {
    TLV_UNSPEC,
    TLV_U8,
    TLV_U16,
    TLV_U32,
    TLV_U64,
    TLV_STRING,
    TLV_FLAG,
    TLV_MSECS,
    TLV_NESTED,
    TLV_NESTED_COMPAT,
    TLV_NUL_STRING,
    TLV_BINARY,
    TLV_S8,
    TLV_S16,
    TLV_S32,
    TLV_S64,
    __TLV_TYPE_MAX,
};

#define TLV_TYPE_MAX (__TLV_TYPE_MAX - 1)

#define TLV_HDRLEN ((int)sizeof(struct tlv_attr))

static inline int tlva_ok(const struct tlv_attr *tlva, int remaining)
{
    return remaining >= (int)sizeof(*tlva) && tlva->len >= 0 &&
           tlva->len <= remaining;
}

static inline struct tlv_attr *tlva_next(const struct tlv_attr *tlva,
                                         int *remaining)
{
    int totlen = tlva->len + sizeof(*tlva);

    *remaining -= totlen;
    return (struct tlv_attr *)((char *)tlva + totlen);
}

static inline void *tlva_data(const struct tlv_attr *tlva)
{
    return (char *)tlva + TLV_HDRLEN;
}

static inline int tlva_len(const struct tlv_attr *tlva)
{
    return tlva->len;
}

static inline int tlva_type(const struct tlv_attr *tlva)
{
    return tlva->type;
}

int tlva_parse(void *tlv_data, size_t tlv_len, struct tlv_attr **tb,
               int maxtype, const struct tlva_policy *policy);

int tlva_memcpy(void *dest, const struct tlv_attr *src, int count);
int tlva_memcmp(const struct tlv_attr *tlva, const void *data, size_t size);

size_t tlva_strlcpy(char *dst, const struct tlv_attr *tlva, size_t dstsize);
int tlva_strcmp(const struct tlv_attr *tlva, const char *str);

/**
 * nla_parse_nested - parse nested attributes
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @nla: attribute containing the nested attributes
 * @policy: validation policy
 *
 * See nla_parse()
 */
static inline int tlva_parse_nested(struct tlv_attr *tb[], int maxtype,
                                    const struct tlv_attr *nla,
                                    const struct tlva_policy *policy)
{
    return tlva_parse(tlva_data(nla), tlva_len(nla), tb, maxtype, policy);
}

/**
 * tlva_get_u64 - return payload of u64 attribute
 * @nla: u64 tlv attribute
 */
static inline u64 tlva_get_u64(const struct tlv_attr *tlva)
{
    u64 tmp;

    tlva_memcpy(&tmp, tlva, sizeof(tmp));

    return tmp;
}

/**
 * tlva_get_u32 - return payload of u32 attribute
 * @tlva: u32 tlv attribute
 */
static inline u32 tlva_get_u32(const struct tlv_attr *tlva)
{
    return *(u32 *)tlva_data(tlva);
}

/**
 * tlva_get_u16 - return payload of u16 attribute
 * @tlva: u16 tlv attribute
 */
static inline u16 tlva_get_u16(const struct tlv_attr *tlva)
{
    return *(u16 *)tlva_data(tlva);
}

/**
 * tlva_get_u8 - return payload of u8 attribute
 * @tlva: u8 tlv attribute
 */
static inline u8 tlva_get_u8(const struct tlv_attr *tlva)
{
    return *(u8 *)tlva_data(tlva);
}

/**
 * tlva_for_each_attr - iterate over a stream of attributes
 * @pos: loop counter, set to current attribute
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define tlva_for_each_attr(pos, head, len, rem) \
    for (pos = head, rem = len; tlva_ok(pos, rem); pos = tlva_next(pos, &(rem)))

/**
 * tlva_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#define tlva_for_each_nested(pos, tlva, rem) \
    tlva_for_each_attr(pos, tlva_data(tlva), tlva_len(tlva), rem)

#endif /* CORE_TLV_ATTR */
