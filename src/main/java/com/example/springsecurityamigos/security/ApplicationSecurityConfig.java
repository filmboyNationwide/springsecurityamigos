package com.example.springsecurityamigos.security;

import com.example.springsecurityamigos.auth.ApplicationUserService;
import com.example.springsecurityamigos.jwt.JwtTokenVerifier;
import com.example.springsecurityamigos.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

import java.util.concurrent.TimeUnit;

import static com.example.springsecurityamigos.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalAuthentication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception{
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        XorCsrfTokenRequestAttributeHandler delegate = new XorCsrfTokenRequestAttributeHandler();
        // set the name of the attribute the CsrfToken will be populated on
        delegate.setCsrfRequestAttributeName("_csrf");
        // Use only the handle() method of XorCsrfTokenRequestAttributeHandler and the
        // default implementation of resolveCsrfTokenValue() from CsrfTokenRequestHandler
        CsrfTokenRequestHandler requestHandler = delegate::handle;

        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authentication -> authentication))
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)
                //This version works!
//                .csrf((csrf) -> csrf
//                        .csrfTokenRepository(tokenRepository)
//                        .csrfTokenRequestHandler(requestHandler)
//                )
//               This version created a CRSF token in the header, but it didn't work with the write requests.
//                .csrf(csrf -> {
//                    csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//                })
                .authorizeRequests(auth -> {
                    auth.requestMatchers("/","index","/css/*", "/js/*").permitAll();
                    auth.requestMatchers("/api/**").hasRole(STUDENT.name());
                    auth.requestMatchers("/admin").hasRole(ADMIN.name());
                    //This is now done with annotations in the Controller
//                    auth.requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission());
//                    auth.requestMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission());
//                    auth.requestMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission());
//                    auth.requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name());
                })
//                .formLogin(form -> {
//                    form
//                            .loginPage("/login")
//                            .permitAll()
//                            .defaultSuccessUrl("/courses", true)
//                            .passwordParameter("password") //This allows you to change the name of the fields, must also be changed in login.html or wherever they are referenced
//                            .usernameParameter("username");
//                })
//                .rememberMe(remember -> {
//                    remember
//                            .rememberMeCookieName("remember-me")
//                            .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                            .key("somethingverysecured")
//                            .rememberMeParameter("remember-me");
//                })
//                .logout(logout -> {
//                    logout
//                            .logoutUrl("/logout")
//                            .logoutSuccessUrl("/login")
//                            .clearAuthentication(true)
//                            .invalidateHttpSession(true)
//                            .deleteCookies("JSESSIONID", "remember-me");
//                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }


    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails annaSmithUser = User.builder()
//                .username("annasmith")
//                .password(passwordEncoder.encode("password"))
//  //              .roles(STUDENT.name())  //ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails lindaUser = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMIN.name()) //ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("password123"))
// //               .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                annaSmithUser,
//                lindaUser,
//                tomUser
//        );
//    }
}
