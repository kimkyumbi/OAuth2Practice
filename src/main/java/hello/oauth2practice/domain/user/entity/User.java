package hello.oauth2practice.domain.user.entity;

import hello.oauth2practice.global.enums.AuthReferrerType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicUpdate;
import hello.oauth2practice.global.enums.Role;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@DynamicUpdate
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "username", nullable = false)
    private String username; // 로그인한 사용자의 이름

    @Column(name = "email", nullable = false)
    private String email; // 로그인한 사용자의 이메일

    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false)
    // 사용자가 로그인한 서비스(ex) google, naver..)
    private AuthReferrerType authReferrerType;

    // 사용자의 이름이나 이메일을 업데이트하는 메소드
    public User updateUser(String username, String email) {
        this.username = username;
        this.email = email;

        return this;
    }

    public static User buildMemberWithOauthInfo(String email, AuthReferrerType authRefType) {
        return User.builder()
                .email(email)
                .authReferrerType(authRefType)
                .build();
    }
}
