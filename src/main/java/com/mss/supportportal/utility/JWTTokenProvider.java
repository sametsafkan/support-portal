package com.mss.supportportal.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.mss.supportportal.domain.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.mss.supportportal.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

@Slf4j
@Component
public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * This method generates token
     *
     * @param userPrincipal
     * @return generated token
     */
    public String getGeneratedToken(UserPrincipal userPrincipal) {
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create()
                .withIssuer(GET_ARRAYS_LLC)
                .withAudience(GET_ARRAYS_ADMINISTRATION)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withExpiresAt(getExpireDate())
                .withArrayClaim(AUTHORITIES, claims).sign(HMAC512(secret.getBytes()));
    }

    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    public Authentication getAuthentication(String userName, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, null, authorities);
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return authenticationToken;
    }

    public boolean isTokenValid(String userName, String token) {
        JWTVerifier verifier = getVerifier();
        return StringUtils.isEmpty(userName) && isTokenExpired(verifier, token);
    }

    public String getSubject(String token){
        JWTVerifier verifier = getVerifier();
        return  verifier.verify(token).getSubject();
    }

    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expireDate = verifier.verify(token).getExpiresAt();
        return expireDate.before(new Date());
    }

    private String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getVerifier();
        return verifier
                .verify(token)
                .getClaim(AUTHORITIES)
                .asArray(String.class);
    }

    private JWTVerifier getVerifier() {
        try {
            Algorithm algorithm = HMAC512(secret);
            return JWT
                    .require(algorithm)
                    .withIssuer(GET_ARRAYS_LLC)
                    .build();
        } catch (JWTVerificationException e) {
            log.error("Token verification error", e);
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
    }

    private Date getExpireDate() {
        return Date
                .from(LocalDateTime.now()
                        .plusSeconds(EXPIRATION_TIME)
                        .atZone(ZoneId.systemDefault())
                        .toInstant());
    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        return userPrincipal
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList())
                .toArray(new String[0]);
    }
}
