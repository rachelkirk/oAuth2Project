package com.tts.oauth2demo;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@RestController
public class Oauth2demoApplication extends WebSecurityConfigurerAdapter {

        @GetMapping("/user")
        public Map<String, Object> user (@AuthenticationPrincipal OAuth2User principal)
        {
            return Collections.singletonMap("login", principal.getAttribute("login"));
        }
         
        @Override
        protected void configure(HttpSecurity http) throws Exception
        {
            http.authorizeRequests()
                    .antMatchers("/", "/error").permitAll()
                    .anyRequest().authenticated()
                  .and()
                  //.exceptionHandling()
                 //     .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
               //   .and()
                  .oauth2Login().defaultSuccessUrl("/", true)
                  .and()
                  .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                      .logoutSuccessUrl("/").deleteCookies("JSESSIONID")
                      .invalidateHttpSession(true);
        }
        
        
	public static void main(String[] args) {
	   
		SpringApplication.run(Oauth2demoApplication.class, args);
	}

}
