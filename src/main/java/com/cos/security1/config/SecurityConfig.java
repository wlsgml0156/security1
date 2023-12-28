package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

// 구글 로그인이 완료된 뒤 후처리
// 1. 코드 받기(인증) 2.액세스토큰(권한) 3. 사용자 프로필 정보를 가져온다.
// 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도함.
// 4-2. 추가 정보가 필요하다면 추가 정보를 받아야함.


@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그을 진행
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip. 코드x, 액세스토큰+사용자정보를 한 방에
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
    }
}
