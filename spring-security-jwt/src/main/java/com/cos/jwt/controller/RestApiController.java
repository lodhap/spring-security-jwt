package com.cos.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.dao.UserDao;
import com.cos.jwt.model.User;

@RestController
public class RestApiController {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	UserDao dao;

	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}
	@PostMapping("token")
	public String token() {
		return "<h1>token</h1>";
	}
	
	// 회원가입
	// 포스트맨으로 테스트 가능
	@PostMapping("join")
	public String join(@RequestBody User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		dao.save(user);
		return "회원가입완료";
	}
	
	@GetMapping("/api/vl/user/test")
	public String userTest() {
		return "<h1>/api/vl/user/test</h1>";
	}
	
	@GetMapping("/api/vl/manager/test")
	public String managerTest() {
		return "<h1>/api/vl/manager/test</h1>";
	}
	
	@GetMapping("/api/vl/admin/test")
	public String adminTest() {
		return "<h1>/api/vl/admin/test</h1>";
	}
}
