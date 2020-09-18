package com.proje.config;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;
	// Tokenin gecerlilik suresi 45 dk
	public static final long JWT_TOKEN_VALIDITY = 45 * 60;

	@Value("${jwt.secret}")
	private String secret;
	private int refreshExpirationDateInMs; //refresh tokenin tanýmlandýgý kýsým
	
	@Value("${jwt.refreshExpirationDateInMs}")
	public void setRefreshExpirationDateInMs(int refreshExpirationDateInMs) {
		this.refreshExpirationDateInMs = refreshExpirationDateInMs;
	}
	
	public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))  //refresh tokenin oluþtugu kýsým geçerlilik süresi apllication.properties dosyasýnda 
				.setExpiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
				.signWith(SignatureAlgorithm.HS512, secret).compact();

	}
	
	@RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
	public ResponseEntity<?> refreshtoken(HttpServletRequest request) throws Exception {
		// From the HttpRequest get the claims
		DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");

		Map<String, Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);
		String token = jwtUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
		return ResponseEntity.ok(new AuthenticationResponse(token));
	}

	public Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
		Map<String, Object> expectedMap = new HashMap<String, Object>();
		for (Entry<String, Object> entry : claims.entrySet()) {
			expectedMap.put(entry.getKey(), entry.getValue());
		}
		return expectedMap;
	}

	
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);  //Kullanýcý adýný jwt tokenden alan fonksiyon
	}

	
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);  //Jwt tokenin son kullanma tarihini alan fonksiyon
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);	//Tokenden herhangi bir bilgi almak için gizli anahtara ihtiyacýmýz oluyor gizli anahtarý aldýðýmýz fonksiyon
		return claimsResolver.apply(claims);
	}
    
	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token); // Alýnan tokenin süresinin dolup dolmadýðýný kontrol eden fonksiyon
		return expiration.before(new Date());
	}

	
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();			// kullanýcý için token oluþturan fonksiyon
		return doGenerateToken(claims, userDetails.getUsername());
	}

	
	private String doGenerateToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public String doGenerateRefreshToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + refreshExpirationDateInMs))
				.signWith(SignatureAlgorithm.HS512, secret).compact();

	}
	
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);						//Alýnan tokenin doðrulandýgý kýsým
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}