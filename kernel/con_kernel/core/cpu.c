#include <linux/cpumask.h>
#include "gnHead.h"
#include "cpu.h"

//当前系统上的cpu数,至少有一颗
int vsec_nr_cpus = 1; 

void vsec_cpu_init(void)
{
    vsec_nr_cpus = num_possible_cpus();
    LOG_INFO("the system has %d possible cpus\n",
        vsec_nr_cpus);
}

void vsec_cpu_uninit(void)
{}