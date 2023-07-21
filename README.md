### 功能

golang 实现的Ldap操作工具

- 实现ldap3原生库中不支持SDDL解析
- 支持SDDL解析
- 支持修改SDDL
- 内置多种搜索语法
- 支持自定义搜索语法

### SDDL解析细节

...

### 版本控制
当前版本：1.2

1.0 以项目功能移植为主，不添加新功能，确保已有功能不出现错误  
2.0 添加修改Ldap属性为主

### 1.0 TODO

**功能类**  
- [x] SSL连接  
- [ ] 导出查询结果  
- [ ] (调研)以当前用户Token查询
- [ ] 支持hash登陆

**搜索模块类**  

计算机查询
- [ ] 查找域机器  
- [ ] 查找域控  

委派查询
- [ ] 查找非约束委派用户    
- [ ] 查找非约束委派机器  
- [ ] 查找约束委派用户  
- [x] 查找资源约束委派用户  

域基本查询
- [ ] 查询域控MAQ  

组查询
- [ ] 域内所有的组  
- [ ] 查询域管组  

用户查询
- [x] 查找所有用户  
- [ ] 查找具有SPN属性的账户  
- [ ] 查找域管账户  
- [x] 查找DCSync账户

### 2.0 TODO

- [x] 添加DCSync权限
- [ ] 激活用户

其他补充  
https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
