package hello.oauth2practice.domain.user.repository;

import hello.oauth2practice.domain.user.entity.User;
import hello.oauth2practice.global.enums.AuthReferrerType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByAuthReferrerTypeAndEmail(AuthReferrerType authRefType, String email);
}

