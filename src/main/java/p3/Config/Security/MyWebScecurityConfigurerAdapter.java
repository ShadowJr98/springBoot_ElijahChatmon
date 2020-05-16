package p3.Config.Security;

import org.apache.catalina.security.SecurityConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;@Configuration


public class MyWebScecurityConfigurerAdapter extends WebSecurityConfigurerAdapter
{
	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

	// NOTE ilker in below setting default value as true, that will be used when this property is not there in application.properties
	@Value("${mh.security.authserver.BCryptPasswordEncoder.usedToEncodePassword:true}")
	private boolean useBCryptPasswordEncoder2encodePassword;
	
	/**
	 * NOTE ilker starting with Spring 5, which spring-boot-starter-parent 2.x uses, have to use a password encoder 
	 *      otherwise password check will fail with below WARN message in logs (console)
	 *      WARN BCryptPasswordEncoder "Encoded password does not look like BCrypt"
	 *      So when spring-boot-starter-parent version is 2.x, then make sure to set "mh.security.authserver.BCryptPasswordEncoder.usedToEncodePassword=true" in application.properties
	 * NOTE ilker BCryptPasswordEncoder always generates a random salt, so if you invoke it 2 times with SAME input, it will return 2 DIFFERENT output
	 * @return encoded rawPassword if {@link #useBCryptPasswordEncoder2encodePassword} == true. Otherwise rawPassword 
	 */
	private String encode(String rawPassword) {
		String password = useBCryptPasswordEncoder2encodePassword ? passwordEncoder().encode(rawPassword) : rawPassword;
		logger.info("--ILKER --> encode({}) with useBCryptPasswordEncoder2encodePassword:{} returning password as {}", rawPassword, useBCryptPasswordEncoder2encodePassword, password);
		return password;
	}
		
	/** NOTE ilker starting with Spring 5, which spring-boot-starter-parent 2.x uses, you are required to use a password encoder while setting password */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				// sample MVC urls
				.antMatchers("/", "/home","/public**").permitAll()	// NOTE ilker urls allowed to see with or without login(without being authenticated == anonymous)
				.antMatchers("/anonymous").anonymous()				// NOTE ilker the difference of this is from above is, if user is logged in, then this page will NOT be accessible. When user is not logged in, this is another way of doing same thing as above, another url allowed to see without login
				.antMatchers("/authenticated", "userSettings/**").authenticated()	// NOTE ilker probably not needed as ".anyRequest().authenticated()" line further below will cover this and "/user" url
				.antMatchers("/admin", "/h2_console/**").hasRole("ADMIN")
				// mh related example MVC urls
				.antMatchers("/cats**").hasRole("catMaster")
				.antMatchers("/dogs**").hasRole("dogMaster")
				.antMatchers("/dogs**").hasAnyRole("dogMaster")
	
				// REST api urls
				.antMatchers("/rest/v1/cats").hasRole("catMaster")
				.antMatchers("/rest/v1/dogs").hasAnyAuthority("dogMaster")	
			
				.anyRequest().authenticated()	// NOTE ilker if not authenticated and trying to access an authenticated url, it will 1st try to go to url, then will be "redirected"(302) to "login" page(with "location" attribute in response pointing to login url), after user logs in, he will go to url 
				.and()
				.formLogin().loginPage("/login").permitAll()
				.and()
				.logout().permitAll()
				;
		
		http.exceptionHandling().accessDeniedPage("/403");
		http.csrf().disable();
		http.headers().frameOptions().disable();
	}

	protected void configure_OLD(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.antMatchers("/admin", "/h2_console/**").hasRole("ADMIN").anyRequest()
				.authenticated()
				.and()
				.formLogin().loginPage("/login").permitAll()
				.and()
				.logout().permitAll();
		http.exceptionHandling().accessDeniedPage("/403");
		http.csrf().disable();
		http.headers().frameOptions().disable();
	}
	
	@Autowired
	public void configureGlobal_(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.withUser("catUser").password(encode("catUser")).roles("catMaster")
				.and()
//				  
				.withUser("dogUser").password(encode("dogUser")).roles("dogMaster").authorities("HaveDogs")
				.and()
				.withUser("developer").password(encode("developer")).roles("DEVELOPER", "ADMIN", "catMaster", "dogMaster").authorities("haveDogs")
				.and()
				.withUser("admin").password(encode("admin")).roles("ADMIN")
				.and();
	}

	private UserDetailsManagerConfigurer<AuthenticationManagerBuilder, InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder>> and() {
		// TODO Auto-generated method stub
		return null;
	}

}