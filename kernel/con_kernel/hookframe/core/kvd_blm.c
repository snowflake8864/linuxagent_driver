#include "kvd_blm.h"

uint64_t kvd_calc_blm_hval(const char* data,
                        size_t len)
{
    size_t i = 0;
    uint64_t val = 0;

    for(;i < len;i++) {
        val += data[i];
    }

    return val;
}

bool kvd_check_blm_hval(const char* data,size_t len,
                        const kvd_blm_hval_t* blm_hval)
{
    uint64_t hval = 0;
    hval = kvd_calc_blm_hval(data,len);
    return ((hval >= blm_hval->hmin) &&
            (hval <= blm_hval->hmax));
}

void kvd_array_blm_hval(const char* arr[],size_t size,
                                kvd_blm_hval_t* blm_hval)
{
    size_t i = 0;
    for(i = 0;i < size;i++) {
        uint64_t hval = 0;
        hval = kvd_calc_blm_hval(arr[i],
                        strlen(arr[i]));

        if(hval < blm_hval->hmin) {
            blm_hval->hmin = hval;
        } else if(hval > blm_hval->hmax) {
            blm_hval->hmax = hval;
        }
    }
}
