package kh.edu.istad.oauth2_authorization_server.repository;

import java.util.Optional;
import kh.edu.istad.oauth2_authorization_server.entity.Authorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationRepository extends JpaRepository<Authorization, String> {
	Optional<Authorization> findByState(String state);
	Optional<Authorization> findByAuthorizationCodeValue(String authorizationCode);
	Optional<Authorization> findByAccessTokenValue(String accessToken);
	Optional<Authorization> findByRefreshTokenValue(String refreshToken);
	Optional<Authorization> findByOidcIdTokenValue(String idToken);
	Optional<Authorization> findByUserCodeValue(String userCode);
	Optional<Authorization> findByDeviceCodeValue(String deviceCode);

	@Query("select a from Authorization a where a.state = :token" +
			" or a.authorizationCodeValue = :token" +
			" or a.accessTokenValue = :token" +
			" or a.refreshTokenValue = :token" +
			" or a.oidcIdTokenValue = :token" +
			" or a.userCodeValue = :token" +
			" or a.deviceCodeValue = :token"
	)
	Optional<Authorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);
}
