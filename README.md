
## 配置：
pom.xml 文件引入如下配置
```xml
<dependency>
    <groupId>org.guzt</groupId>
    <artifactId>shirojwt-spring-boot-starter</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

引入配置后，其实 application.yml不用配置任何信息即可启用 shiro jwt，
当然你可以根据下面的常用默认值决定是否配置

 1. 配置文件默认登录路径 /api/login
 2. 配置文件默认退出路径 /api/logout
 3. 默认Header里jwt的名称 Authorization
 4. 其他默认值请查看源码
 
如果需要配置不同信息，yml文件配置也十分简单：
```yaml

shirojwt:
  login-url: /api/login
  logout-url: /api/logout
  jwtIssuer: yourIssuerName
  token-header-key: Authorization

```

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
        String salt = user.get(UserInfoService.saltKey);
        return new SimpleAuthenticationInfo(token, password, ByteSource.Util.bytes(salt), realmName);
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

### 4. 添加自定义路径配置

**默认已经对swagger进行的过滤，可直接访问swagger页面**

```java
@Component
public class MyExtraFilterRule extends ExtraFilterRule {
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