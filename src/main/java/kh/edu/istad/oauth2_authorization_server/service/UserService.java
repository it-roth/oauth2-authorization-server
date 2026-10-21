package kh.edu.istad.oauth2_authorization_server.service;

import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterRequest;
import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterResponse;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {

	UserRegisterResponse registerUser(UserRegisterRequest request);
}

