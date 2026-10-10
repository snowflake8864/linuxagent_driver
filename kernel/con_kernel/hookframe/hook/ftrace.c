#ifdef FTRACE_HOOK_ENABLED
    // #if defined(__x86_64__) || defined(__i386__)
    //     #define FH_IP(regs)  (regs->ip)
    // #elif defined(__aarch64__)
    //     #define FH_IP(regs)  (regs->pc)
    // #endif
    static u_long kvd_ftrace_enabled = 0;

    static void ftrace_hook_enable(void)
    {
        set_bit(0, &kvd_ftrace_enabled);
    }

    static void ftrace_hook_disable(void)
    {
        clear_bit(0, &kvd_ftrace_enabled);
    }

    static int ftrace_hook_enabled(void)
    {
        return test_bit(0, &kvd_ftrace_enabled);
    }

    static void notrace fh_ftrace_thunk (unsigned long ip, unsigned long parent_ip,
                    struct ftrace_ops *ops, 
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0) || SPEC_VERSION_BUILD == 3
                    struct ftrace_regs* fregs
                #else
                    struct pt_regs* fregs
                #endif
                )
    {
        kvd_sc_hook_t *hook = container_of(ops, kvd_sc_hook_t,ft_ops);
        //这个地方一定要判断是否为空
        //因为如果设置了FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED
        //这里极有可能就是空，在arm64上就是如此
        if(fregs == NULL || !ftrace_hook_enabled()) { return; }

        /* Skip the function calls from the current module. */
        if (!kvd_within_module(THIS_MODULE,parent_ip)) {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0) ||  SPEC_VERSION_BUILD == 3
            ftrace_regs_set_instruction_pointer(fregs,
                (unsigned long) hook->hook_fn);
        #elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
            ftrace_instruction_pointer_set(fregs,
                (unsigned long) hook->hook_fn);
        #else
            instruction_pointer_set(fregs,
                (unsigned long) hook->hook_fn);
        #endif
        }
    }

    volatile void** kvd_find_syscall_table(void);
    const char* get_syscall_name(int index);

    static int resolve_hook_address(kvd_sc_hook_t* hook)
    {
        unsigned long addr = 0;
        const char* name = get_syscall_name(hook->syscall_idx);
        if(!name) { return -EINVAL; }

        //这里只能调用这个函数获取原始系统调用地址，
        //不要用我们查找到的系统调用表去获取
        //因为如果其他人hook系统调用后，我们再用系统调用表直接就会导致崩溃
        addr = kallsyms_lookup_name(name);
        if(!addr) { return -EINVAL; }

        *(hook->org_fn) = (void*)(addr);
        return 0;
    }

    static int ftrace_install_hook(kvd_sc_hook_t* hook)
    {
        int err = 0;
        const char* name;

        //已经hook过，认为是成功
        if(hook->ft_hooked) { return err; }

        err = resolve_hook_address(hook);
        if (err) { return err; }

        hook->ft_ops.func = fh_ftrace_thunk;
        //arm64上不支持FTRACE_OPS_FL_SAVE_REGS参数，
        //要使用FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED
        //FTRACE_OPS_FL_IPMODIFY,这个标识只有在ftrace_set_filter_ip时才需要
        hook->ft_ops.flags = FTRACE_OPS_FL_SAVE_REGS 
                        | FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED;

        name = get_syscall_name(hook->syscall_idx);
        err = ftrace_set_filter(&hook->ft_ops,(char*)name,strlen(name),0);
        if (err) {
            LOG_ERROR("ftrace_set_filter() failed: %d,name: %s\n",err,name);
            return err;
        }

        err = register_ftrace_function(&hook->ft_ops);
        if (err) {
            LOG_ERROR("register_ftrace_function() failed: %d,name: %s\n", err,name);
            return err;
        }

        hook->ft_hooked = true;
        LOG_INFO("ftrace hook %s successfully\n",name);

        return 0;
    }

    static int ftrace_remove_hook (kvd_sc_hook_t* hook)
    {
        int err = 0;

        if(!(hook->ft_hooked)) { return err; }

        err = unregister_ftrace_function(&hook->ft_ops);
        if(err) {
            LOG_ERROR("unregister_ftrace_function() failed: %d\n", err);
        } else {
            hook->ft_hooked = false;
        }

        return err;
    }
#else
    static int ftrace_install_hook(kvd_sc_hook_t* hook)
    {
        return -ENODEV;
    }

    static int ftrace_remove_hook (kvd_sc_hook_t* hook)
    {
        return -ENODEV;
    }

    static void ftrace_hook_enable(void) {}

    static void ftrace_hook_disable(void) {}
#endif

