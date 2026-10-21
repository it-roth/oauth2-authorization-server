package kh.edu.istad.oauth2_authorization_server.service;

import java.util.Set;
import java.util.stream.Collectors;

import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterRequest;
import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterResponse;
import kh.edu.istad.oauth2_authorization_server.entity.User;
import kh.edu.istad.oauth2_authorization_server.mapper.UserMapper;
import kh.edu.istad.oauth2_authorization_server.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final UserMapper userMapper;

	public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, UserMapper userMapper) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.userMapper = userMapper;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = this.userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

		return new org.springframework.security.core.userdetails.User(
				user.getUsername(),
				user.getPassword(),
				user.isEnabled(),
				true,
				true,
				true,
				user.getRoles().stream()
						.map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toSet())
		);
	}

	@Override
	public UserRegisterResponse registerUser(UserRegisterRequest request) {
		if (request.username() == null || request.username().isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username cannot be empty");
		}
		if (request.password() == null || request.password().isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password cannot be empty");
		}
		if (request.email() == null || request.email().isBlank()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot be empty");
		}
		if (this.userRepository.existsByUsername(request.username())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Username is already taken");
		}
		if (this.userRepository.existsByEmail(request.email())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
		}

		User user = this.userMapper.toEntity(request);
		user.setPassword(this.passwordEncoder.encode(request.password()));
		user.setRoles(Set.of("ROLE_USER"));

		User savedUser = this.userRepository.save(user);
		return this.userMapper.toResponse(savedUser, "User registered successfully");
	}
}
