package psjw.jwt.tutorial.util;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

@Slf4j
@NoArgsConstructor
public class SecurityUtil {

    //Security Context의 Authentication 객체를 이용해 username을 리턴해 주는 간단한 util method
    public static Optional<String> getCurrentUsername(){
        // SecurityContextHolder.getContext()에 Authentication 저장 시점 JwtFilter의 doFilter 메소드에서
        // Request가 들어올때 SecurityContext에 Authentication 객체를 저장해서 사용
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String username = null;
        if(authentication.getPrincipal() instanceof UserDetails){
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        }else if(authentication.getPrincipal() instanceof String){
            username = (String) authentication.getPrincipal();
        }

        return Optional.ofNullable(username);
    }
}
