package kh.edu.istad.oauth2_authorization_server.controller;

import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterRequest;
import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterResponse;
import kh.edu.istad.oauth2_authorization_server.mapper.UserMapper;
import kh.edu.istad.oauth2_authorization_server.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;
	private final UserMapper mapper;

	public UserController(UserService userService, UserMapper mapper) {
		this.userService = userService;
		this.mapper = mapper;
	}

	@PostMapping("/register")
	@ResponseStatus(HttpStatus.CREATED)
	public UserRegisterResponse registerUser(@RequestBody UserRegisterRequest request) {
		return userService.registerUser(request);
	}
}
