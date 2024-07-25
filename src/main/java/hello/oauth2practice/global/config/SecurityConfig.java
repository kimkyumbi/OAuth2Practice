package hello.oauth2practice.global.config;

import hello.oauth2practice.domain.oAuth.service.CustomOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomOauth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(
                (auth) -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated()
        );

        http.oauth2Login(
                (oauth) -> oauth
                        .defaultSuccessUrl("/oauth/loginInfo", true)
                        .userInfoEndpoint(
                                (userInfoEndpointConfig) -> userInfoEndpointConfig.userService(customOAuth2UserService)
                        )
        );

        return http.build();
    }
}
