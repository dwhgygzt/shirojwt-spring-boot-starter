
## 配置：
pom.xml 文件引入如下配置
```xml
<dependency>
    <groupId>org.guzt</groupId>
    <artifactId>shirojwt-spring-boot-starter</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

引入配置后， application.yml简单配置即可启用 Shiro JWT ：

```yaml
shirojwt:
    enable: true
```

当然你可以根据下面的常用默认值决定是否个性化配置
 1. 文件默认登录路径 /api/login
 2. 文件默认退出路径 /api/logout
 3. 默认Header里jwt的名称 Authorization
 4. 默认值token超时时限1个小时, 自动刷新token时间为40分钟
 5. token 后台刷新后，标注response Status code为201，前端取 header中的Authorization值替换即可
 6. 默认未启用认证授权方法缓存，可设置开关为true开启缓存
 


## 用法：
### 1. 用户登录后生成 token方法
下面是一个简单的测试类
```java
@RestController
@RequestMapping("/api")
public class UserInfoController {

    // 用于查询用户信息的 service
    @Resource
    private UserInfoService userInfoService;

    @PostMapping("login")
    public Map<String, String> login(String userName, String password) {
        // 你的登录代码验证逻辑
        Map<String, String> loginInfo = userInfoService.login(userName, password);
        if (loginInfo == null || loginInfo.isEmpty()) {
            BusinessException.create("用户名或密码错误");
        }
        // 登录验证通过后 生成token给前端
        assert loginInfo != null;
        loginInfo.put("token", JwtUtil.sign(userName, 
                        loginInfo.get(UserInfoService.passwordKey), 
                        loginInfo.get(UserInfoService.saltKey)));
        return loginInfo;
    }

    @GetMapping("logout")
    public String logout() {
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            subject.logout();
        }
        return "退出成功";
    }
}
```

### 2. 前端访问后台接口，http请求中 HEADER 必须带有token
 
|  KEY   | VALUE  |
|  ----  | ----  |
| Authorization  | 登录接口获得的token值 |

### 3. shiro验证token合法性
重写 JwtBussinessService 类即可，覆盖里面几个方法, 

java 代码中使用如下：
```java
@Service
public class MyJwtBussinessService extends JwtBussinessService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());


    public MyJwtBussinessService() {
        logger.info("MyJwtBussinessService 初始化");
    }

    @Override
    public AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals, String realmName) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        logger.debug("进入 授权 doGetAuthorizationInfo");
        logger.debug("the toke is  {}", principals.toString());
        String userName = JwtUtil.getUserName(principals.toString());
        // 模拟从数据库中根据用户名查询出用户
        Map<String, String> user = UserInfoService.MYSQL_USER_TABLE.get(userName);
        String spit = ",";
        // 该用户具有哪些权限
        for (String permission : user.get(UserInfoService.permissionsKey).split(spit)) {
            authorizationInfo.addStringPermission(permission);
        }
        // 该用户具有哪些角色
        for (String role : user.get(UserInfoService.rolesKey).split(spit)) {
            authorizationInfo.addRole(role);
        }

        return authorizationInfo;
    }

    @Override
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth, String realmName) throws AuthenticationException {
        String token = (String) auth.getCredentials();
        logger.debug("进入 认证 doGetAuthenticationInfo");
        logger.debug("the toke is  {}", token);
        // token是否过期
        Date expiresDate = JwtUtil.getExpiresAt(token);
        if (expiresDate == null) {
            throw new IncorrectCredentialsException("token 不正确");
        } else if (expiresDate.before(new Date())) {
            throw new ExpiredCredentialsException("token 过期了");
        }
        // 验证 token是否有效
        String userName = JwtUtil.getUserName(token);
        if (userName == null) {
            throw new IncorrectCredentialsException("token 不正确");
        }
        // 验证用户是否存在
        Map<String, String> user = UserInfoService.MYSQL_USER_TABLE.get(userName);
        if (user == null) {
            throw new UnknownAccountException("用户不存在");
        }
        // 用户最终认证
        String password = user.get(UserInfoService.passwordKey);
        // 盐值（生成用户密码时候，冗余一个字段，随机产生一个字符串）
        String salt = user.get(UserInfoService.saltKey);
       // 注意这里的盐值采用 ShiroByteSource 封装
        return new SimpleAuthenticationInfo(token, password,  new ShiroByteSource(salt), realmName);
    }

    @Override
    public void onAccessDenied(HttpServletRequest request, HttpServletResponse response, boolean isTokenExists, ShiroException ex) throws IOException {
        //  这里的 ShiroException 分为两类 一类认证异常  一类权限检查不通过异常
        //  AuthenticationException 认证异常
        //  AuthorizationException 权限检查不通过异常
        defaultPrintJson(response, "{\"code\":\"-1\",\"data\":{\"bussinessCode\":\"401\"},\"message\":\"" + ex.getLocalizedMessage() + "\"}");
    }

    @Override
    public String refreshOldToken(String oldToken) {
        // 刷新 token
        String userName = JwtUtil.getUserName(oldToken);
        Map<String, String> user = UserInfoService.MYSQL_USER_TABLE.get(userName);
        return JwtUtil.sign(userName, user.get(UserInfoService.passwordKey), user.get(UserInfoService.saltKey));
    }
}
```

**默认已经对swagger进行的过滤，可直接访问swagger页面**
**如果要引入其他Bean 请务必使用懒加载方式，防止自定义的AOP失效，因为ExtraFilterRule所在的配置类会被提前初始化**

```java
@Component
public class MyExtraFilterRule extends ExtraFilterRule {
    
    // 请务必使用懒加载方式注入bean
    // yourBusinessBean 例如为菜单查询类，查询出所有按钮权限菜单
    @Lazy
    @Service
    private YourBusinessBean yourBusinessBean;

    @Override
    public void setExtraFilterRule(LinkedHashMap<String, String> filterRuleMap) {
        // 不检查某些路径
        filterRuleMap.put("/api/init", "noSessionCreation,anon");
       // 添加自定义过滤器配置 myTestFilter 就是自己的过滤器
        filterRuleMap.put("/api/selectUserInfoByUserName", "noSessionCreation,myTestFilter,jwt,jwtPerms[dd]");
    }
}
```

### 5. 添加自定义过滤器
**如果要引入其他Bean 请务必使用懒加载方式，防止自定义的AOP失效，因为ExtraFilter所在的配置类会被提前初始化**
```java
@Component
public class MyExtraFilter extends ExtraFilter {
    @Override
    public void setExtraFilter(LinkedHashMap<String, Filter> filterMap) {
        filterMap.put("myTestFilter", new MyTestFilter());
    }
}

/**
 * 自定义过滤器, 请勿使用 @Bean 或 @Service
 *
 * admin
 */
public class MyTestFilter extends AuthorizationFilter {

    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        logger.info("没有别的事情，就是表示进过了过滤器 MyTestFilter");
        return Boolean.TRUE;
    }
}
```

### 6. 默认已经添加的过滤器配置
|  名称   | 作用  |
|  ----  | ----  |
| jwt  | jwt认证 |
| myCorsFilter  | 支持跨域，默认支持 |
| jwtPerms  | URL 上的权限认证 |
| jwtRoles  | URL 上的角色认证 |


### 7. 基于URL的权限认证
一般情况下针对基于URL的权限认证，说白了就是按钮权限认证，也即对后台某个Controller方法的权限认证。
所谓权限认证，就是你是否有相应的权限或角色标识才可调用该controller里面的某个方法。

这里做法一般两种， 1. 基于权限注解  2. 基于URL过滤器配置
#### 基于注解
用法如下：
```java
/**
 * 测试 shirojwt
 *
 * @author admin
 */
@RestController
@RequestMapping("/api")
public class UserInfoController {
 
    // 需要 权限 admin:update 才可访问这个方法
    @RequiresPermissions("admin:update")
    @PutMapping("updateUser")
    public String updateUser(@RequestBody Map<String, String> user) {
        userInfoService.updateUser(user);
        return "success";
    }
 
    // 需要 admin或user角色才能访问这个方法
    @RequiresRoles(value = {"admin","user"})
    @GetMapping("getUserInfoByUserName")
    public Map<String, String> getUserInfoByUserName(String userName) {
        return userInfoService.getUserByUserName(userName);
    }

}

```
当用户访问 上面controller层里面任意一个方法时，shiro会调用上文中 doGetAuthorizationInfo  
方法，该方法作用就是从数据库或缓存中根据 JWT 取出用户具有的角色和权限，然后Shiro框架会自动判定用户是否具有
访问该方法的权限，如果没有将抛出 UnauthorizedException 异常， 用户可使用全局异常进行捕获反馈给前端。

这里说明一下 在此之前用户已经进过JWT 认证了，如果认证不通过不会到这一步的。


#### 基于URL过滤器配置
上文已经提过，本starter已经默认注册了 权限角色验证的过滤器,且支持自定义URL过滤配置

|  名称   | 作用  |
|  ----  | ----  |
| jwtPerms  | URL 上的权限认证 |
| jwtRoles  | URL 上的角色认证 |

重复上面的文章 覆写ExtraFilterRule类即可。

**默认已经对swagger进行的过滤，可直接访问swagger页面**
**如果要引入其他Bean 请务必使用懒加载方式，防止自定义的AOP失效，因为ExtraFilterRule所在的配置类会被提前初始化**

```java
@Component
public class MyExtraFilterRule extends ExtraFilterRule {
    
    // 请务必使用懒加载方式注入bean
    // MenuRoleService 角色菜单权限关系处理service
    @Lazy
    @Service
    private MenuRoleService menuRoleService;

    @Override
    public void setExtraFilterRule(LinkedHashMap<String, String> filterRuleMap) {
        List<Menu> buttons = menuRoleService.listAllButtonMenu();
        for( Menu item : buttons ){
            // item.getPathUrl() 是按钮对应的后端路径
            // item.getPerm() 是按钮应的权限标识，表示这个URL需要该权限标识才可访问
            filterRuleMap.put(item.getPathUrl(), "noSessionCreation,jwt,jwtPerms["+ item.getPerm() +"]");
        }
    }
}
```

这里如果用户权限认证不通过时候，会调用上文中 MyJwtBussinessService 里面的 onAccessDenied 方法。
此时 ShiroException 为 UnauthorizedException，你可以根据具体的异常类别做出打印或跳转信息给前端。

这里列出 ShiroException 的具体常用的几种子类，以便你做出具体的业务逻辑处理。

|  类别   | 说明  |
|  ----  | ----  |
| NoTokenAuthenticationException  |【jwt验证】 header里面未携带jwt |
| ProgramErrorAuthenticationException  | 【jwt验证】jwt验证程序500错误 |
| ExpiredCredentialsException  | 【jwt验证】jwt过期，这个需要你自己认证方法里面抛出 |
| ExpiredCredentialsException  | 【jwt验证】jwt过期，这个需要你自己认证方法里面抛出 |
| IncorrectCredentialsException  | 【jwt验证】jwt格式错误，这个需要你自己认证方法里面抛出  |
| UnauthorizedException  | 【权限验证】 权限认证不通过统一抛出该异常 |




### 8. 基于URL的动态权限认证
所谓动态 就是可以在管理系统里面随意添加一条或删除一条URL 认证记录，这里暂不建议这样做，
这里非要做其实是要刷新Shiro里面缓存的URL 拦截配置，说穿了就是将里面的一个LinkHashMap清空重新
填充数据。

- 不建议原因1  现在都是分布式部署，你要刷新全部的机器上的应用
- 不建议原因2  一般都是有新功能上线才会有这样的事情，建议滚动发布即可，挨个重启服务测试
- 不建议原因3  现在很多的微服务认证都转向API网关层认证，当然网关认证也可结合shirojwt，网关一般也是多台部署
  一般滚动发布即可。
  
### 9. 关于缓存管理

认证授权方法 ShiroJWT 支持缓存。

1. yml中设置enable-cache-manager 属性为true

```yaml

shirojwt:
    enable: true
    enable-cache-manager: true

```

2. 继承缓存工具类，覆盖里面的方法即可，缓存时间是当前token剩余的有效期时长

```java
public class MyCacheService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 将对象放入缓存
     *
     * @param key        存储的key，这里一律String 类型
     * @param value      存储对象
     * @param timeToLive 存活时间
     * @param timeUnit   时间单位
     * @param <T>        value的类型
     */
    <T> void setObject(String key, T value, Long timeToLive, TimeUnit timeUnit) {
        logger.info("请覆盖此方法");
    }

    /**
     * 从缓存中获取对象
     *
     * @param key 存储的key，这里一律String 类型
     * @return 具体对象
     */
    Object getObject(String key) {
        logger.info("请覆盖此方法");
        return null;
    }

    /**
     * 从缓存中删除对象
     *
     * @param key 存储的key，这里一律String 类型
     */
    void removeObject(String key) {
        logger.info("请覆盖此方法");
    }


}

```


这里针对token的认证授权还是建议开发自行开发处理，
 在认证 和 授权两个方法里面通过redis缓存进行自定义逻辑处理。