package com.example.bemap.repository;


import com.example.bemap.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.*;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByUsername(String username);
    // Spring phân tích tên hàm "existsByUsername"
    // -> Tự generate SQL:
    // SELECT CASE WHEN COUNT(*) > 0 THEN TRUE ELSE FALSE END
    // FROM users WHERE username = ?;
    // Trả về true/false.

    User findByUsername(String username);
    // Spring phân tích tên hàm "findByUsername"
    // -> Tự generate SQL:
    // SELECT * FROM users WHERE username = ?;
    // Nếu tìm thấy thì ánh xạ row -> User object, không thì trả về null.




}