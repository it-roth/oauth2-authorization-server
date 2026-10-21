package kh.edu.istad.oauth2_authorization_server.dto;

import java.util.Set;

public record UserRegisterResponse(
		String id,
		String username,
		String email,
		String fullName,
		Set<String> roles,
		String message
) {
}
