package com.example.bemap.service;


import com.example.bemap.entity.User;
import com.example.bemap.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    // Constructor injection: Spring inject repo vào service.
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void saveUser(User user) {
        // Gọi repository.save -> JPA decide: INSERT (nếu id null) hoặc UPDATE (nếu id tồn tại).
        // Sau save, DB đã nhận dữ liệu (thực tế commit tùy config transaction), object User sẽ có id nếu là insert.
        userRepository.save(user);
    }



    // kiểm tra tồn tại username
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username); // SELECT COUNT...
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username); // SELECT * WHERE username = ?
    }
}