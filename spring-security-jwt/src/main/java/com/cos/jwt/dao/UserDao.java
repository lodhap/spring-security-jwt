package com.cos.jwt.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.cos.jwt.model.User;

@Repository
public class UserDao {

	@Autowired
	SqlSessionTemplate session;
	
	public User findByUsername(String username) {
		return null;
//		return session.selectOne("findByUsername", username);
	}
	
}
