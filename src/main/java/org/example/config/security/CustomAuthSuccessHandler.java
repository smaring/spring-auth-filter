package org.example.config.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

  @Autowired
  HttpSession session;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if ( authentication instanceof CustomAuthToken ) {
      log.debug( "setting attribute in session" );
      CustomAuthToken customAuthToken = (CustomAuthToken) authentication;
      session.setAttribute( "name", customAuthToken.getPrincipal() );
    } else {
      log.debug( "not an instance of CustomAuthToken" );
    }
    super.onAuthenticationSuccess(request, response, authentication);
  }

}
