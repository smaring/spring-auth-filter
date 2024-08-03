package org.example.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomAuthProvider implements AuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    CustomAuthToken customAuthToken = (CustomAuthToken) authentication;
    if ( customAuthToken == null || customAuthToken.getPrincipal() == null ) {
      log.warn( "problem with authentication" );
      throw new BadCredentialsException("No name provided");
    }
    log.debug( "setting setAuthenticated to true" );
    customAuthToken.setAuthenticated( true );
    return customAuthToken;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals( CustomAuthToken.class );
  }
}
