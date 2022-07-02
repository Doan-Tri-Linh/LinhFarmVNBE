package com.hiephoafarm.main.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors();
		http.authorizeRequests()
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.antMatchers("/product/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_EMPLOYEE')")
			.antMatchers("/orders/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_EMPLOYEE')")
			.and()
			.formLogin().loginPage("/auth/login")
			.loginProcessingUrl("/auth/process-login")
			.defaultSuccessUrl("/orders/index")
			.failureUrl("/auth/login?error")
			.usernameParameter("username")
			.passwordParameter("password")
			.and()
			.logout().logoutUrl("/auth/logout")
			.logoutSuccessUrl("/auth/login?logout")
			.and()
			.exceptionHandling().accessDeniedPage("/auth/accessDenied");
		
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource()
	{
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("https://linhfarm.vercel.app/"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
