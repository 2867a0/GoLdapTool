### 功能

golang 实现的 Ldap 小工具

- 实现ldap3原生库中不支持SDDL解析(支持SDDL解析)
- 支持修改SDDL
- 以普通用户查询DCSync
- 内置多种搜索语法
- 支持自定义搜索语法

### SDDL解析细节

...

### 版本控制
当前版本：2.6

1.0 以项目功能移植为主，不添加新功能，确保已有功能不出现错误  
2.0 添加修改Ldap属性为主  
3.0 ldap相关漏洞检测功能（ADCS漏洞证书模版查询、26923检测）

### 1.0 TODO

**功能类**  
- [x] SSL连接  
- [x] 导出查询结果  
- [x] (调研)以当前用户Token查询
- [x] 支持hash登陆

**搜索模块类**  

计算机查询
- [x] 查找域机器  
- [x] 查找域控  

委派查询
- [x] 查找非约束委派用户    
- [x] 查找非约束委派机器  
- [x] 查找约束委派用户  
- [x] 查找资源约束委派用户  

域基本查询
- [x] 查询域控MAQ  

组查询
- [x] 域内所有的组  
- [x] 查询域管组  

用户查询
- [x] 查找所有用户  
- [x] 查找具有SPN属性的账户  
- [x] 查找域管账户  
- [x] 查找DCSync账户

### 2.0 TODO

- [x] 添加DCSync权限
- [ ] 修改RBCD
- [ ] 激活用户
- [ ] 使用示例
- [ ] 查询DNS记录

其他补充  
https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
