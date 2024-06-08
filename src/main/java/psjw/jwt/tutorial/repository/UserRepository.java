package psjw.jwt.tutorial.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import psjw.jwt.tutorial.entity.User;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>{
    //username을 이용하여 User 정보를 가져오고 권한정보들도 함께 가져옴
    // @EntityGraph는 쿼리가 수행이 될때 Lazy 조회가 아니고 Eager 조회
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
