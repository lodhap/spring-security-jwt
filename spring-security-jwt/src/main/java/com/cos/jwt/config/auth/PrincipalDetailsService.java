package com.cos.jwt.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwt.dao.UserDao;
import com.cos.jwt.model.User;

@Service
public class PrincipalDetailsService implements UserDetailsService{

	private final UserDao dao;
	
	public PrincipalDetailsService(UserDao dao) {
		super();
		this.dao = dao;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = dao.findByUsername(username); 
		return new PrincipalDetails(userEntity);
	}
		
}
