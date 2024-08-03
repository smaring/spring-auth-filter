package org.example.config.security;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

  @Autowired
  CustomAuthProvider customAuthProvider;

  @Autowired
  CustomAuthSuccessHandler customAuthSuccessHandler;

  @Bean
  public AuthenticationManager authManager(HttpSecurity http) throws Exception {
    AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
    authenticationManagerBuilder.authenticationProvider(customAuthProvider);
    return authenticationManagerBuilder.build();
  }

  @Bean
  public SecurityContextRepository securityContextRepository() {
    return new DelegatingSecurityContextRepository(
            new RequestAttributeSecurityContextRepository(),
            new HttpSessionSecurityContextRepository()
    );
  }


  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http,
                                          SecurityContextRepository securityContextRepository,
                                          AuthenticationManager authManager) throws Exception {

    CustomAuthFilter customAuthFilter = new CustomAuthFilter(authManager);
    customAuthFilter.setSecurityContextRepository( securityContextRepository );
    customAuthFilter.setAuthenticationSuccessHandler(customAuthSuccessHandler);

    return http
            .csrf(AbstractHttpConfigurer::disable)
            .addFilterAt(customAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .sessionManagement( session -> {
              session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
            })
            .authorizeHttpRequests( request -> {
              request.anyRequest().authenticated();
            })
            .authenticationManager( authManager )
            .build();

  }

}
