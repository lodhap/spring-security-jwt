package com.cos.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
 
	private final CorsFilter corsFilter;
	
    public SecurityConfig(CorsFilter corsFilter) {
        this.corsFilter = corsFilter;
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
		
		
		http.csrf().disable();
			// 세션 사용 x 설정
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.addFilter(corsFilter) //@CrossOrigin (인증x), 시큐리티 필터에 등록 인증(o)
		.formLogin().disable() // form태그 로그인 방식 사용 x
		.httpBasic().disable() // 기본적인 http로그인 방식 x 
		
		.authorizeRequests()
		.antMatchers("api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("api/v1/manager/**")
		.access("hasRole('ROLE_ADMIN')")
		
		.anyRequest().permitAll();
	}
	
}
