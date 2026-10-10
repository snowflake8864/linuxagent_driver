## 测试用例说明

### 编译
* make                        -->编译出名为khookframe的内核模块

### 使用
* 编译出khookframe内核模块后，直接insmod加载至内核
* 使用root用户，使用如下指令开启或关闭syscall hook;通过dmesg可以查看相关内核日志
```bash
    #开启syscall hook
    echo -n 1 >/sys/khookframe/switch
    #关闭syscall hook
    echo -n 0 >/sys/khookframe/switch
```
* khookframe内核模块卸载只有在关闭syscall hook后才可以卸载

