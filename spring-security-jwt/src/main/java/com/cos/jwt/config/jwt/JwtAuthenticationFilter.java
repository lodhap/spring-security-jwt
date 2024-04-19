package com.cos.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

//로그인시도, 로그인성공 객체

// 스프링 시큐리티엣 UsernamePasswordAuthenticationFilter가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함
// formLogin().disable()해서 이 필터 작동을 안함
// 다시 쓰려면 시큐리티 필터에 등록을 다시 해줘야함
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	// 이 필터는 AuthenticationManager를 받아야 사용이 가능함
	private final AuthenticationManager authenticationManager;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		super();
		this.authenticationManager = authenticationManager;
	}

	// 1. attemptAuthentication
	//login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("로그인시도중...");
		
		//1. username, password 받아서
		//2. 정상인지 로그인 시도를 해보는 거에요. authenticationManager로 
		//로그인 시도를 하면! PrincipalDetailsService가 호출이 됩니다.
		// loadUserByUsername이 자동으로 실행됩니다.
		//3. PrincipalDetails를 세션에 담고
		//4. JWT토큰을 만들어서 응답해주면 됨.
		// 세션에 담는 이유: 안담으면 권한관리가 안됨
		
		try {
			// 바이트로 유저정보가 담겨있음
//			System.out.println(request.getInputStream().toString());
//			BufferedReader br = request.getReader();
//			String input = null;
//			while ((input = br.readLine())!=null) {
//				System.out.println(input);
//			}
			
			//json데이터를 객체로 파싱해주는 클래스
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			//authenticationManager에 토큰을 만들어서 넣어주면 로그인 시도를 해준다.
			// Authentication을 반환받는다.
			
			// 토큰만들기
			// formLogin 사용시 자동으로 해주던 작업
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			//로그인시도
			//PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨. 정상이면 Authentication가 리턴됨.
			// DB에 있는 username과 password와 일치한다는 것.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("로그인 인증됨: " + principalDetails.getUser().getUsername());
			System.out.println("=================");
			
			// Authentication객체가 session영역에 저장되야하고 그 방법이 return.
			// 리턴의 이유는 권한관리를 security가 대신 해주기 때문에 편하려고 하는 것.
			// 굳이 JWT를 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한처리 때문에 세션에 넣어주는 것이다.
			return authentication;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("=================");
		return null;
	}
	
	
	//2. successfulAuthentication
	// 인증 성공시 실행되는 함수
	// JWT토큰 생성후 요청자에게 응답
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		// 부모 클래스의 successfulAuthentication 메서드를 호출합니다. 
		// 이 호출이 응답을 초기화하거나 다른 필터로 제어를 넘겨서 응답 헤더를 설정하기 전에 응답이 커밋될 수 있습니다.
		//super.successfulAuthentication(request, response, chain, authResult);
		
		System.out.println("successfulAuthentication: 로그인 인증됨");

		// Authentication에서 pricipal 얻기
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		// JWT 토큰 제작
		//java-jwt 라이브러리 사용
		// builder 패턴임
//		System.out.println("시간테스트: " + System.currentTimeMillis());
		String jwtToken = JWT.create()
				.withSubject("cos토큰") //토큰이름
				//만료시간 : 짧게 줄 것 (10분)
				// 현재시간 + 만료시간 형식
				// System.currentTimeMillis() : 현재시간
				// 만료시간 : 1000당 1초
				.withExpiresAt(new Date(System.currentTimeMillis()+(10*60*1000)))
				// 비공개 클레임
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUsername())
				//HMAC512 암호화방식 : SECRET키 보유
				.sign(Algorithm.HMAC512("cos"));
		
		// 응답은 반드시 "Bearer " 한칸 꼭 띄워야한다.
		//System.out.println("Bearer "+jwtToken);
		response.addHeader("Authorization", "Bearer "+jwtToken);
	}
	
	//스프링시큐리티에서 서버가 세션id가 유효한지 판단하는 것은 자동으로 할 수 있음
	//jwt가 유효한지 판단하는 것은 자동으로 하지 못함
	//jwt가 유효한지 판단하는 필터를 만들어야함
}
