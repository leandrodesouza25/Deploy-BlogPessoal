package br.org.generation.ProjetoBlog.Seguranca;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired 
	private UserDetailsServiceImpl service;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(service);
		
		auth.inMemoryAuthentication()
		.withUser("root")
		.password(passwordEncoder().encode("root"))
		.authorities("ROLE_USER");
	
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
        .antMatchers("/**").permitAll() 
        .antMatchers("/usuarios/logar").permitAll()
        .antMatchers("/usuarios/cadastrar").permitAll()
        .antMatchers(HttpMethod.GET, "/postagens").permitAll()
        .antMatchers(HttpMethod.GET, "/tema").permitAll()
        .antMatchers(HttpMethod.POST, "/postagens").permitAll()
        .antMatchers(HttpMethod.POST, "/tema").permitAll()
        .antMatchers(HttpMethod.PUT, "/postagens").permitAll()
        .antMatchers(HttpMethod.PUT, "/tema").permitAll()
        .antMatchers(HttpMethod.DELETE, "/postagens").permitAll()
        .antMatchers(HttpMethod.DELETE, "/tema").permitAll();

	}
	
	
}


