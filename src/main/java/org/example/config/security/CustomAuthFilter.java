package org.example.config.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class CustomAuthFilter extends AbstractAuthenticationProcessingFilter {

  private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("**","GET");

  public CustomAuthFilter( AuthenticationManager authenticationManager ) {
    super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
  }


  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    log.debug( "attempting authentication ..." );
    String name = request.getParameter( "name" );

    if ( name == null ) {
      throw new BadCredentialsException("No name provided");
    }

    SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER1");
    List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<SimpleGrantedAuthority>();
    grantedAuthorities.add(authority);
    CustomAuthToken customAuthToken = new CustomAuthToken( name, grantedAuthorities );

    return this.getAuthenticationManager().authenticate( customAuthToken );
  }


}
