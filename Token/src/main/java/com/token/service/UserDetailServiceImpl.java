package com.token.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.token.model.User;
import com.token.repo.UserRepo;

import jakarta.transaction.Transactional;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepo userRepo;
	
	@Override
	@Transactional
	 public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	    User user = userRepo.findByUsername(username)
	        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

	    return UserDetailsImpl.build(user);
	  }

}
