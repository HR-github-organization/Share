# **初识**Spring Security

### 1.导入Sercrity jar包

```xml
 		<dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
```

### 2.编写继承类操作Security方法

继承WebSecurityConfigurerAdapter方法

```java
@Configuration 
@EnableWebSecurity //拥有操作Security的权限
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    //登录成功处理逻辑
    @Resource
    private MyAuthenticationSuccessHandler authenticationSuccessHandler;//自定义方法
    
    
     //处理登录失败逻辑
    @Resource
    private MyAuthenticationFailureHandler authenticationFailureHandler;
    
    
      //权限拒绝处理逻辑
    @Resource
    private MyAccessDeniedHandler accessDeniedHandler;
    
     //重新登录加载类
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();//自定义类，用于编写loadUserByUsername方法
    }
    //重写密码方法
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    //重写验证方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }
    
    private CorsConfigurationSource CorsConfigurationSource() {
        CorsConfigurationSource source =   new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");    //同源配置，*表示任何请求都视为同源，若需指定ip和端口可以改为如“localhost：8080”，多个以“，”分隔；
        corsConfiguration.addAllowedHeader("*");//header，允许哪些header，本案中使用的是token，此处可将*替换为token；
        corsConfiguration.addAllowedMethod("*");    //允许的请求方法，PSOT、GET等
        ((UrlBasedCorsConfigurationSource) source).registerCorsConfiguration("/**",corsConfiguration); //配置允许跨域访问的url
        return source;
    }
     /**
     * 配置spring security的控制逻辑
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 新加入(cors) CSRF  取消跨站请求伪造防护 //由于使用的是JWT，我们这里不需要csrf
        http.cors().configurationSource(CorsConfigurationSource());//允许跨域访问
        http.cors().and().csrf().disable();
        http.authorizeRequests()

                /** 解决跨域 **/
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()

                /** 任何尚未匹配的URL都只需要对用户进行身份验证  每个请求的url必须通过这个规则  RBAC 动态 url 认证 **/
                //.anyRequest().access("@rbacauthorityservice.hasPermission(request,authentication)")

                //登录
                .and()
                .formLogin()//开启登录, 定义当需要用户登录时候，转到的登录页面，默认post方法
                .loginProcessingUrl("/user/login") //自定义的登录路径
                .successHandler(authenticationSuccessHandler)// 登录成功
                //.failureHandler(authenticationFailureHandler)// 登录失败

                // 不需要session
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //异常处理(权限拒绝、登录失效等)
                .and().exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)//权限拒绝处理逻辑
                //.authenticationEntryPoint(myAuthenticationEntryPoint)//匿名用户访问无权限资源时的异常处理

                //验证token
                .and()
                .addFilter(new AuthenticationTokenFilter(authenticationManager()));//自定义方法
        ;
    }
}
```



### 3.自定义类重写UserDetailsService，实现loadUserByUsername方法

需要重写UserDetailsService

注意security不能使用明文验证，必须使用加密

```java

//自定义securuity的验证方法，重写下面的loadUserByUserName方法
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;//自定义操作数据库方法，此处不做具体内容展示

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //获取当前登录用户
        EUser eUser = userMapper.getEUserByNumber(username);
        if (eUser == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String pwd = passwordEncoder.encode(eUser.getPassword());
        eUser.setPassword(pwd); //如果没有加密，需要使用默认方式加密，
        
        //使用set将权限存储
        Set<String> allAuthorityList = userMapper.getAllAuthorityById(eUser.getId());//获取权限集合的方法
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : allAuthorityList) { //遍历权限集合
            //System.out.println(authority);
            grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }
        //密码验证在User中实现
        return new User(eUser.getUsername(), eUser.getPassword(), grantedAuthorities);
    }
}

```



### 4.注意问题

必须在启动类中将Mapper文件目录（操作数据库方法）用MapperScan引用路径

```java
@SpringBootApplication
@MapperScan("com.cyh.company.mapper")
public class CompanyApplication {
    public static void main(String[] args) {
        SpringApplication.run(CompanyApplication.class, args);
    }
}
```



### 5.自定义类书写登录成功返回逻辑

重写AuthenticationSuccessHandler方法

authentication中存储了loadUserByUsername方法中返回的User当中具有的属性值。

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//登录成功处理逻辑
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private ObjectMapper objectMapper;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //Authentication：登录成功后的返回数据
        //System.out.println(authentication.getName()+","+authentication.getAuthorities());

        //UserDetails后续会将该接口提供的用户信息封装到认证
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        SecurityContextHolder.getContext().setAuthentication(authentication);//重新设置用户

        //获取token
        String token = TokenUtil.generateToken(userDetails);
        Map<String,Object> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_OK));
        map.put("msg", "登录成功");
        map.put("token", token);
        map.put("enumber",authentication.getName());
        map.put("codeList",authentication.getAuthorities());
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(map));
        writer.flush();
        writer.close();
    }
}

```

### 6.token生成方法

```java
package com.cyh.company.utils;

import com.cyh.company.entity.EUser;
import com.cyh.company.mapper.UserMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.*;

@Component
public class TokenUtil implements Serializable {
    private static String SECRECT_KEY = "admins";//jwt 加密解密密钥, 暂时使用admins
    private static Long timeout = 60 * 60 * 2 * 1000L; //过期时间2小时
    public static final String TOKEN_PREFIX = "Bearer "; //前缀
    public static final String AUTHORIZATION = "Authorization";//表头授权


    /**
     * 从数据声明生成令牌
     *
     * @param claims 数据声明
     * @return 令牌
     */
    private static String generateToken(Map<String, Object> claims) {
        Date expirationDate = new Date(System.currentTimeMillis() + timeout);
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, SECRECT_KEY)//签名算法
                .compact();
    }

    /**
     * 从令牌中获取数据声明
     *
     * @param token 令牌
     * @return 数据声明
     */
    private static Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(SECRECT_KEY).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    /**
     * 生成令牌
     *
     * @param userDetails 用户
     * @return 令牌
     */
    public static String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(2);
        claims.put("sub", userDetails.getUsername());
        claims.put("created", new Date());

        claims.put(AUTHORIZATION, userDetails.getAuthorities());
        return TOKEN_PREFIX + generateToken(claims);
    }

    /**
     * 得到权限字符串
     */
    public static String getAuthorStr( String authority) {

        String authoryStr = "";
        String[] authorityList = StringUtils.strip(authority, "[]").split(",");
        for (String s : authorityList) {
            System.out.println(StringUtils.strip(s,"{}"));
            authoryStr = authoryStr + s + ",";
        }
        return authoryStr.substring(0, authoryStr.length() - 1);
    }

    /**
     * 从令牌中获取用户名
     *
     * @param token 令牌
     * @return 用户名
     */
    public static String getUsernameFromToken(String token) {
        String username;
        try {
            Claims claims = getClaimsFromToken(token);
            username = claims.getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * 判断令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public static Boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 刷新令牌
     *
     * @param token 原令牌
     * @return 新令牌
     */
    public static String refreshToken(String token) {
        String refreshedToken;
        try {
            Claims claims = getClaimsFromToken(token);
            claims.put("created", new Date());
            refreshedToken = generateToken(claims);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }

    /**
     * 验证令牌
     *
     * @param token       令牌
     * @param userDetails 用户
     * @return 是否有效
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        EUser user = (EUser) userDetails;
        String username = getUsernameFromToken(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    /**
     * 从Token中获取用户角色
     */
    public static String getUseAythoritys(String token) {
        Claims claims = Jwts.parser().setSigningKey(SECRECT_KEY).parseClaimsJws(token).getBody();
        return claims.get("Authorization").toString();
    }
}

```

### 7.前端请求时token验证

自定义方法，继承BasicAuthenticationFilter

```java


/**
 * token的校验
 * 该类继承自BasicAuthenticationFilter，在doFilterInternal方法中，
 * 从http头的Authorization 项读取token数据，然后用Jwts包提供的方法校验token的合法性。
 * 如果校验通过，就认为这是一个取得授权的合法请求
 */
public class AuthenticationTokenFilter extends BasicAuthenticationFilter {


    public AuthenticationTokenFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String url = request.getRequestURI();
        //String AUTHORIZATION = "Authorization";//表头授权
        String header = request.getHeader(TokenUtil.AUTHORIZATION);

        if (header == null || !header.startsWith(TokenUtil.TOKEN_PREFIX)) {
            getResponse(response, "token不合法！");
            //chain.doFilter(request,response);//执行下一个过滤器
            return;
        }
        final String authToken = header.substring(TokenUtil.TOKEN_PREFIX.length());//真正的token
        if (TokenUtil.isTokenExpired(authToken)) {
            getResponse(response, "token过期！");
            return;
        }
        String username = TokenUtil.getUsernameFromToken(authToken);
        if (username == null || username == "") {
            getResponse(response, "token错误！");
            return;
        }
        // 如果请求头中有token,并且格式正确，则进行解析，重新用户设置认证信息
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(header));
        super.doFilterInternal(request, response, chain);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {

        //获取到名字
        String token = tokenHeader.replace(TokenUtil.TOKEN_PREFIX, "");
        String username = TokenUtil.getUsernameFromToken(token);

        //获取到权限字符串，然后切分
        String authoritys = TokenUtil.getUseAythoritys(token);
        String[] authorityList = StringUtils.strip(authoritys, "[]").split(", ");

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        String str = "authority=";
        for (String authority : authorityList) {
            String curString = authority.substring(str.length() + 1, authority.length() - 1);
            grantedAuthorities.add(new SimpleGrantedAuthority(curString));
        }
        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null,
                    grantedAuthorities);//返回一个新的User对象
        }
        return null;
    }

    /**
     * 组装token验证失败的返回
     */
    private HttpServletResponse getResponse(HttpServletResponse response, String msg) throws IOException, ServletException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_CREATED));//201默认未登录，或者登录时效已过
        map.put("msg", msg);
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        System.out.println(map);
        writer.write(objectMapper.writeValueAsString(map));
        writer.flush();
        writer.close();
        return response;
    }

}

```



### 8.使用注解方法规定权限

必须在启动类开始注解

注解的功能在于返回一个新的User对象中是否包含有注解当中拥有的权限

```java
@SpringBootApplication
@MapperScan("com.cyh.company.mapper")
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class CompanyApplication {

    public static void main(String[] args) {
        SpringApplication.run(CompanyApplication.class, args);
    }

}
```

在Controller方法上添加注解（此处使用权限验证方式）

```java
@CrossOrigin
@RestController
@RequestMapping(value = "/worktype")
public class WorkTypeController {
/**
     * 获取所有工作类型
     * */
    @PreAuthorize("hasAnyAuthority('worktype:getAllWorkeType')")//判断用户是否具有权限
    @RequestMapping(value = "/getAllWorkeType",method = RequestMethod.GET)
    @ResponseBody
    public Object getAllWorkType() {
        return null;
    }
}
```

### 9.处理权限拒绝逻辑

重写AccessDeniedHandler方法，实现handle方法

```java

import com.fasterxml.jackson.databind.ObjectMapper;
/**
 * 权限拒绝处理逻辑
 * */
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Autowired
    private ObjectMapper objectMapper;
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        Map<String,String> map = new LinkedHashMap<>();
        map.put("code", String.valueOf(HttpServletResponse.SC_FORBIDDEN));
        map.put("msg", "用户没有权限");
        response.setContentType("Application/json;charset=UTF-8");
        Writer writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(map));
        writer.flush();
        writer.close();
    }
}

```



