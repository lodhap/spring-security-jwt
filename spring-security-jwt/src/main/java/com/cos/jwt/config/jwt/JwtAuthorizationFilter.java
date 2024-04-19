package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.dao.UserDao;
import com.cos.jwt.model.User;

// 권한이 필요한 주소요청시 토큰검증, 권한부여, 세션저장 객체

// 시큐리티가 Filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

	private UserDao dao;
	
	
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserDao dao) {
		super(authenticationManager);
		this.dao = dao;
//		System.out.println("BasicAuthenticationFilter 생성자");		
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
//		super.doFilterInternal(request, response, chain);
		
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨");
		
		// Header에서 토큰 얻기
		String jwtHeader = request.getHeader("Authorization");
//		System.out.println("jwtHeader " + jwtHeader);
		
		// header에 토큰 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰을 검증해서 정상적인 사용자인지 확인
		//"Bearer "제거
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
//		System.out.println(jwtToken);
		
		// 서명을 통한 무결성과 인증 검증과정 (헤더와 페이로드가 유지되었는지)
		// 1. Algorithm.HMAC512() : HMAC512 알고리즘을 사용하여 SHA-512 해시 함수로 키 "cos"를 사용하는 알고리즘을 설정
		// 2. JWT.require() : 주어진 알고리즘으로 JWT검증을 위한 Verification 객체를 생성
		// 3. build() : Verification 객체를 구성
		// 4. verify() : 주어진 jwt가 유효한지 검사하고, 유효하면 DecodedJWT를 반환. 이 객체를 통해 토큰의 클레임 등을 액세스할 수 있습니다.
		
		// 5. getClaim("username").asString() : 클래임 객체를 반환받고 문자열로 변환
		
		// 착각하지 말아야할게 verify까지는 서명 부분을 통해 header, payload의 무결성을 검증한 것이고,
		// claim은 서명에서 복호화한게 아닌 base64url로 인코딩되어있던 값을 디코드해서 가져온 것이다.
		String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
//		System.out.println(username);
		
		// 서명이 정상적으로 됨
		// 권한부여!
		if(username!=null) {
			User userEntity = dao.findByUsername(username);
			System.out.println("유저엔티티: " + userEntity);
			
			//JWT 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			System.out.println("디테일 " +principalDetails +" :   " +principalDetails.getAuthorities());
			System.out.println(authentication);
			// 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			// 필터체인을 타게하면 됨
			chain.doFilter(request, response);
		}
	}
	
	

}
