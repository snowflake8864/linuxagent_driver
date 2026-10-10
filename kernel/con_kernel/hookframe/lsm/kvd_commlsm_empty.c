#warning "lsm unsupported"

static int comm_lsm_init_hook(void)
{
    LOG_INFO("lsm init: unsupported!\n");
    return 0;
}

static void comm_lsm_uninit_hook(void)
{
}

static int comm_lsm_enable(void)
{
    return -ENOTSUPP;
}

static int comm_lsm_disable(void)
{
    return -ENOTSUPP;
}

static int comm_lsm_is_enabled(void)
{
    return 0;
}

static char * comm_lsm_hook_mode(void)
{
    return "lsm-unsupported";
}

static int comm_lsm_register_hook(struct kvd_security_operations *hooks)
{
    LOG_INFO("lsm fun register: unsupported!\n");
    return -ENOTSUPP;
}

static int comm_lsm_unregister_hook(struct kvd_security_operations *hooks)
{
    return -ENOTSUPP;
}
