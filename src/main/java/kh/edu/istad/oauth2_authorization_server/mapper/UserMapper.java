package kh.edu.istad.oauth2_authorization_server.mapper;

import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterRequest;
import kh.edu.istad.oauth2_authorization_server.dto.UserRegisterResponse;
import kh.edu.istad.oauth2_authorization_server.entity.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

	public User toEntity(UserRegisterRequest request) {
		if (request == null) {
			return null;
		}
		return new User(
				request.username(),
				request.password(),
				request.email(),
				request.fullName()
		);
	}

	public UserRegisterResponse toResponse(User user, String message) {
		if (user == null) {
			return null;
		}
		return new UserRegisterResponse(
				user.getId(),
				user.getUsername(),
				user.getEmail(),
				user.getFullName(),
				user.getRoles(),
				message
		);
	}
}
