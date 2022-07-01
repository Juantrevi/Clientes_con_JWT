package com.example.datajp;

import com.example.datajp.Auth.Handler.LoginSuccesHandler;
//import com.example.datajp.Auth.filterJWT.CustomDsl;
import com.example.datajp.Auth.filterJWT.CustomDsl;
import com.example.datajp.Auth.filterJWT.JWTAuthenticationFilter;

import com.example.datajp.Services.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableGlobalAuthentication
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //Para usar las anotaciones @Secured y @PreAuthorize en los controladores
@Configuration
public class SpringSecurityConfig {

    @Autowired
    private LoginSuccesHandler succesHandler;
    @Autowired
    private MvcConfig mvcConfig;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private JpaUserDetailsService jpaUserDetailsService;




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {



        http.authorizeHttpRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale").permitAll()
                .antMatchers("/ver/**").hasAnyRole("USER")
                .antMatchers("/uploads/**").hasAnyRole("USER")
                .antMatchers("/form/**").hasAnyRole("ADMIN")
                .antMatchers("/eliminar/**").hasAnyRole("ADMIN")
                .antMatchers("/factura/**").hasAnyRole("ADMIN")
                .anyRequest().authenticated()
                /*.and()
                .formLogin()
                .successHandler(succesHandler)
                .loginPage("/login")
                .permitAll()  //PARA USAR JWT
                .and()
                .logout()
                .permitAll().and().exceptionHandling().accessDeniedPage("/error_403")*/
                .and()
//                .addFilter(new JWTAuthenticationFilter(authenticationManager))
                .apply(new CustomDsl())
                .and()
                .csrf()
                .disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

@Autowired
    public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception{
        build.userDetailsService(jpaUserDetailsService).passwordEncoder(passwordEncoder);
}

}
