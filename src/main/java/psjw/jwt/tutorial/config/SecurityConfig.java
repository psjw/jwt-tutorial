package psjw.jwt.tutorial.config;

import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import psjw.jwt.tutorial.jwt.JwtAccessDeniedHandler;
import psjw.jwt.tutorial.jwt.JwtAuthenticationEntryPoint;
import psjw.jwt.tutorial.jwt.JwtSecurityConfig;
import psjw.jwt.tutorial.jwt.TokenProvider;

@EnableWebSecurity//Web 보안을 활성화하겠다는 Annotation
//추가 적인 설정을 위해서 WebSecurityConfigurer를 implements or WebSecurityConfigurerAdapter를 extends
@EnableMethodSecurity(prePostEnabled = true) //@PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해 적용
@Configuration
@AllArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //h2console 접속 url : jdbc:h2:mem:testdb
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                //Token 사용하는 방시이므로 csrf를 disabled함
                .csrf(AbstractHttpConfigurer::disable)

                //HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll() //"/api/hello" 에 대한 요청은 인증없이 접근허용, 토큰받기, 회원가입제외
                            .requestMatchers(PathRequest.toH2Console())
                            .permitAll() //h2-console pass
                            .anyRequest().authenticated();  //나머지 요청들은 모두 인증 받아야된다.
                })
                .exceptionHandling(exceptionHandler -> {
                    exceptionHandler.accessDeniedHandler(jwtAccessDeniedHandler)
                            .authenticationEntryPoint(jwtAuthenticationEntryPoint);
                })
                //세션을 사용하지 않기 때문에 STATELESS 지정
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // enable h2-console
                .headers(headers ->
                        headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )
                //JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 추가
                .with(new JwtSecurityConfig(tokenProvider), jwtSecurityConfig -> {});
        return http.build();
    }

}
