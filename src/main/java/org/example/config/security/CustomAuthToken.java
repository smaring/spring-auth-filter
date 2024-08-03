package org.example.config.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomAuthToken extends AbstractAuthenticationToken {

  private String name;

  public CustomAuthToken(String name, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.name = name;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return this.name;
  }
}
