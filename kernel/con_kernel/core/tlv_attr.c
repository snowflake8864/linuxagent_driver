#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "gnHead.h"
#include "gnkernel.h"
#include "tlv_attr.h"

static const u16 tlva_attr_minlen[TLV_TYPE_MAX + 1] = {
    [TLV_U8] = sizeof(u8),     [TLV_U16] = sizeof(u16),
    [TLV_U32] = sizeof(u32),   [TLV_U64] = sizeof(u64),
    [TLV_MSECS] = sizeof(u64), [TLV_NESTED] = TLV_HDRLEN,
    [TLV_S8] = sizeof(s8),     [TLV_S16] = sizeof(s16),
    [TLV_S32] = sizeof(s32),   [TLV_S64] = sizeof(s64),
};

static int validate_tlva(const struct tlv_attr *tlva, int maxtype,
                         const struct tlva_policy *policy)
{
    const struct tlva_policy *pt;
    int minlen = 0, attrlen = tlva_len(tlva), type = tlva_type(tlva);

    if (type <= 0 || type > maxtype)
        return 0;

    pt = &policy[type];

    BUG_ON(pt->type > TLV_TYPE_MAX);

    switch (pt->type) {
    case TLV_FLAG:
        if (attrlen > 0)
            return -ERANGE;
        break;

    case TLV_NUL_STRING:
        if (pt->len)
            minlen = min_t(int, attrlen, pt->len + 1);
        else
            minlen = attrlen;

        if (!minlen || memchr(tlva_data(tlva), '\0', minlen) == NULL)
            return -EINVAL;
        /* fall through */

    case TLV_STRING:
        if (attrlen < 1)
            return -ERANGE;

        if (pt->len) {
            char *buf = tlva_data(tlva);

            if (buf[attrlen - 1] == '\0')
                attrlen--;

            if (attrlen > pt->len)
                return -ERANGE;
        }
        break;

    case TLV_BINARY:
        if (pt->len && attrlen > pt->len)
            return -ERANGE;
        break;

    case TLV_NESTED_COMPAT:
        if (attrlen < pt->len)
            return -ERANGE;
        if (attrlen < (pt->len))
            break;
        if (attrlen < (pt->len) + TLV_HDRLEN)
            return -ERANGE;
        tlva = tlva_data(tlva) + (pt->len);
        if (attrlen < (pt->len) + TLV_HDRLEN + tlva_len(tlva))
            return -ERANGE;
        break;
    case TLV_NESTED:
        /* a nested attributes is allowed to be empty; if its not,
         * it must have a size of at least NLA_HDRLEN.
         */
        if (attrlen == 0)
            break;
        break;
    default:
        if (pt->len)
            minlen = pt->len;
        else if (pt->type != TLV_UNSPEC)
            minlen = tlva_attr_minlen[pt->type];

        if (attrlen < minlen)
            return -ERANGE;
    }

    return 0;
}

int tlva_parse(void *tlv_data, size_t tlv_len, struct tlv_attr **tb,
               int maxtype, const struct tlva_policy *policy)
{
    const struct tlv_attr *tlva;
    int rem, err;

    memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

    tlva = tlv_data;
    tlva_for_each_attr(tlva, tlv_data, tlv_len, rem)
    {
        u16 type = tlva_type(tlva);
        // LOG_DEBUG("tlv_for_each_attr: type[%d]\n", type);
        if (type > 0 && type <= maxtype) {
            if (policy) {
                err = validate_tlva(tlva, maxtype, policy);
                if (err < 0)
                    goto errout;
            }

            tb[type] = (struct tlv_attr *)tlva;
        }
    }

    if (unlikely(rem > 0)) {
        LOG_ERROR("tlv: %d bytes leftover after parsing attributes \n", rem);
    }

    err = 0;
errout:
    return err;
}

/**
 * tlva_memcpy - Copy a tlv attribute into another memory area
 * @dest: where to copy to memcpy
 * @src: tlv attribute to copy from
 * @count: size of the destination area
 *
 * Note: The number of bytes copied is limited by the length of
 *       attribute's payload. memcpy
 *
 * Returns the number of bytes copied.
 */
int tlva_memcpy(void *dest, const struct tlv_attr *src, int count)
{
    int minlen = min_t(int, count, tlva_len(src));

    memcpy(dest, tlva_data(src), minlen);
    if (count > minlen)
        memset(dest + minlen, 0, count - minlen);

    return minlen;
}

/**
 * tlva_memcmp - Compare an attribute with sized memory area
 * @tlva: tlv attribute
 * @data: memory area
 * @size: size of memory area
 */
int tlva_memcmp(const struct tlv_attr *tlva, const void *data, size_t size)
{
    int d = tlva_len(tlva) - size;

    if (d == 0)
        d = memcmp(tlva_data(tlva), data, size);

    return d;
}

/**
 * tlva_strlcpy - Copy string attribute payload into a sized buffer
 * @dst: where to copy the string to
 * @tlva: attribute to copy the string from
 * @dstsize: size of destination buffer
 *
 * Copies at most dstsize - 1 bytes into the destination buffer.
 * The result is always a valid NUL-terminated string. Unlike
 * strlcpy the destination buffer is always padded out.
 *
 * Returns the length of the source buffer.
 */
size_t tlva_strlcpy(char *dst, const struct tlv_attr *tlva, size_t dstsize)
{
    size_t srclen = tlva_len(tlva);
    char *src = tlva_data(tlva);

    if (srclen > 0 && src[srclen - 1] == '\0')
        srclen--;

    if (dstsize > 0) {
        size_t len = (srclen >= dstsize) ? dstsize - 1 : srclen;

        memset(dst, 0, dstsize);
        memcpy(dst, src, len);
    }

    return srclen;
}

/**
 * tlva_strcmp - Compare a string attribute against a string
 * @tlva: tlv string attribute
 * @str: another string
 */
int tlva_strcmp(const struct tlv_attr *tlva, const char *str)
{
    int len = strlen(str);
    char *buf = tlva_data(tlva);
    int attrlen = tlva_len(tlva);
    int d;

    if (attrlen > 0 && buf[attrlen - 1] == '\0')
        attrlen--;

    d = attrlen - len;
    if (d == 0)
        d = memcmp(tlva_data(tlva), str, len);

    return d;
}
