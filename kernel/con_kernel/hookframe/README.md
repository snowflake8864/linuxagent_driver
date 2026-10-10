## Skylar kernel hook frame
### Note
* Linux客户端内核hook框架1.0版本;支持syscall-hook,LSM-hook机制，并提供内核写保护控制机制
* 提供内核源码接口级调用，使用者直接调用相关函数接口实现自身需要的hook功能
* 对于syscall-hook,LSM-hook调用者要严格遵守linux内核syscall,LSM的使用逻辑及其实现
* 代码中大量以khf开头的函数，khf是kernel hook frame的简写
* 支持x86,x86_64,arm64,mips64,sw64等处理器架构平台
* 兼容标版Linux系统，及常见的国产操作系统平台: Deepin/UOS,中标/银河kylin,方德,凝思等
  
### 代码目录结构
* core              -->核心逻辑代码
* hook              -->syscall hook逻辑
* exec 				-->进程启动hook逻辑
* lsm 				-->lsm hook
* test              -->测试用例
