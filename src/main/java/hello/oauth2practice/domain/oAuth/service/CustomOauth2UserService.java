package hello.oauth2practice.domain.oAuth.service;

import hello.oauth2practice.domain.user.entity.User;
import hello.oauth2practice.domain.user.repository.UserRepository;
import hello.oauth2practice.global.enums.AuthReferrerType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import hello.oauth2practice.global.enums.Role;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Service
public class CustomOauth2UserService implements OAuth2UserService {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegateOauth2UserService;
    private final UserRepository userRepository;

    public CustomOauth2UserService(UserRepository userRepository) {
        this.delegateOauth2UserService = new DefaultOAuth2UserService();
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // OAuth2User 객체를 생성하고 delegateOauth2UserService의 loadUser 메서드를 호출해서 OAuth2UserRequest에서
        // 어떤 서비스로 로그인하였는지와 엑세스 토큰, 추가적인 파리미터들을 찾아서 저장
        OAuth2User oAuth2User = delegateOauth2UserService.loadUser(userRequest);

        /**
         * oAuth2User 객체로부터 속성(attribute)들을 key - value 형식의 Map으로 가져옴
         * oAuth2User는 OAuth2 인증 후 제공자로부터 받은 사용자 정보를 포함하는 객체
         * 이 객체는 사용자의 프로필 정보, 이메일 주소, 이름 등 다양한 속성들을 포함할 수 있음
         * getAttributes() 메서드는 이러한 속성들을 맵 형태로 반환
         */
        Map<String, Object> oAuthAttributes = oAuth2User.getAttributes();

        /**
         * userRequest는 OAuth2 인증 요청에 대한 정보를 포함하는 객체
         * getClientRegistration() 메서드로 현재 인증 요청과 관련된 클라이언트 등록 정보를 반환
         * getRegistrationId() 메서드로 이 클라이언트 등록 정보에서 제공자(ex: google, naver, kakao)의 ID를 가져옴
         * 이 정보를 통해 애플리케이션은 사용자가 어떤 제공자를 통해 로그인했는지 알 수 있음
         *  예를 들어, provider 변수가 "google"이면 사용자는 Google을 통해 로그인한 것
         */
        final String provider = userRequest.getClientRegistration().getRegistrationId();

        String providerId;
        AuthReferrerType authRefType;

        // 만약 provider가 null이면 AuthenticationServiceException을 던짐
        if (provider == null) throw new AuthenticationServiceException("oauth provider not found");

        // switch문 / provider.toLowerCase()로 provider에 들어오는 문자열을 전부 소문자로 변환함
        switch (provider.toLowerCase()) {
            // provider가 google일때
            case "google" -> {
                // providerId에 위에서 사용자의 정보들을 맵 형태로 반환한 값에서 email을 가져옴
                providerId = oAuthAttributes.get("email").toString();
                authRefType = AuthReferrerType.GOOGLE;
            }
            // provider가 naver일때
            case "naver" -> {
                // providerId에 Map 함수를 사용해 key - value 형식으로 위에서 사용자의 정보들을 맵 형태로 반환한 값에서 email을 넣어줌
                providerId = ((Map<String, Object>) oAuthAttributes.get("response")).get("email").toString();
                authRefType = AuthReferrerType.NAVER;
            }
            // 두 케이스 중에서 해당되는 경우가 없다면 올바르지 않은 oauth provider라는 오류 던지기
            default -> throw  new IllegalArgumentException("올바르지 않은 oauth provider입니다");
        }

        User user = getUser(authRefType, providerId);

        // 사용자 정보를 담기 위한 변수들을 선언
        // 각 변수는 특정 사용자 속성(attribute)과 관련된 값을 저장합니다.
        String nameAttribute = "id"; // 사용자 ID를 나타내는 속성의 키
        Long id = user.getId(); // 사용자 ID를 member 객체에서 가져온 값

        String roleAttribute = "role"; // 사용자 역할을 나타내는 속성의 키
        Role role = user.getRole();

        String providerAttribute = "provider"; // 로그인 제공자를 나타내는 속성의 키
        String providerIdAttribute = "provider_id"; // 제공자의 ID를 나타내는 속성의 키

        String lastLoginTimeIdAttribute = "last_login_time"; // 마지막 로그인 시간을 나타내는 속성의 키
        LocalDateTime lastLoginTime = LocalDateTime.now(); // 현재 시간을 가져와 마지막 로그인 시간으로 설정

        // 위에서 선언한 변수들을 사용하여 HashMap을 생성
        // Map.of() 메서드는 지정된 키와 값을 가진 불변 맵을 생성합니다.
        // 이 불변 맵을 HashMap 생성자의 인자로 전달하여 가변 맵을 생성합니다.
        Map<String, Object> attributes = new HashMap<>(Map.of(
                nameAttribute, id, // "id" 키에 사용자 ID 값을 매핑
//                roleAttribute, role, // "role" 키에 사용자 역할 값을 매핑
                providerAttribute, provider, // "provider" 키에 로그인 제공자 값을 매핑
                providerIdAttribute, providerId, // "provider_id" 키에 제공자 ID 값을 매핑
                lastLoginTimeIdAttribute, lastLoginTime // "last_login_time" 키에 마지막 로그인 시간 값을 매핑
        ));

        // OAuth2User 객체에서 권한 목록을 가져와 Collection<GrantedAuthority>로 변환
        Collection<GrantedAuthority> authorities = new ArrayList<>(oAuth2User.getAuthorities());
        // user 객체에서 가져온 사용자의 역할의 이름을 권한으로 추가
        authorities.add(new SimpleGrantedAuthority(role.name()));

        return new UserInfo(authorities, attributes, nameAttribute);
    }

    /**
     * 파라미터로 받은 providerId와 authRefType으로 DB에서 유저를 가져오는 메서드
     *
     * @param authRefType
     * @param providerId
     */
    private User getUser(AuthReferrerType authRefType, String providerId) {
        return userRepository.findByAuthReferrerTypeAndEmail(authRefType, providerId)
                // 찾지 못했다면 DB에 저장
                .orElseGet(() -> userRepository.save(User.buildMemberWithOauthInfo(providerId, authRefType)));
    }
}
