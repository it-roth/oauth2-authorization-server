package kh.edu.istad.oauth2_authorization_server.dto;

public record UserRegisterRequest(
		String username,
		String password,
		String email,
		String fullName
) {
}
