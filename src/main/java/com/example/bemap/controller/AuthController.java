package com.example.bemap.controller;

import com.example.bemap.entity.User;
import com.example.bemap.service.UserService;
import com.example.bemap.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userService.existsByUsername(user.getUsername())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Username already exists");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userService.saveUser(user);

        return ResponseEntity.ok("Register successful");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User found = userService.findByUsername(user.getUsername());

        if (found == null || !passwordEncoder.matches(user.getPassword(), found.getPassword())) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        }

        String accessToken = jwtUtil.generateAccessToken(found.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(found.getUsername());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request,
                                            HttpServletRequest httpRequest) {
        String username = (String) httpRequest.getAttribute("username");

        if (username == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Unauthorized");
        }

        String oldPassword = request.get("oldPassword");
        String newPassword = request.get("newPassword");

        User user = userService.findByUsername(username);

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Old password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userService.saveUser(user);

        return ResponseEntity.ok("Password changed successfully");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !jwtUtil.validateToken(refreshToken)) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid or expired refresh token");
        }

        String username = jwtUtil.getUsernameFromToken(refreshToken);
        String newAccessToken = jwtUtil.generateAccessToken(username);

        Map<String, String> response = new HashMap<>();
        response.put("accessToken", newAccessToken);

        return ResponseEntity.ok(response);
    }


    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String email = request.get("email");

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Kiểm tra email có khớp không
        if (user.getEmail() == null || !user.getEmail().equals(email)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Email does not match");
        }

        // Tạo OTP 6 số
        String otp = generateOTP();

        // Lưu OTP vào database (có thời hạn 5 phút)
        user.setOtp(otp);
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, 5);
        user.setOtpExpiry(cal.getTime());
        userService.saveUser(user);

        // TODO: Gửi email thực tế
        // emailService.sendOTP(user.getEmail(), otp);

        Map<String, String> response = new HashMap<>();
        response.put("message", "OTP has been sent to your email");
        // CHỈ để test - trong production KHÔNG trả về OTP
        response.put("otp", otp); // XÓA dòng này khi deploy thật
        response.put("expiresIn", "5 minutes");

        return ResponseEntity.ok(response);
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String otp = request.get("otp");

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Kiểm tra OTP
        String storedOtp = user.getOtp();
        Date otpExpiry = user.getOtpExpiry();

        if (storedOtp == null || !storedOtp.equals(otp)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Invalid OTP");
        }

        if (otpExpiry == null || otpExpiry.before(new Date())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("OTP expired");
        }

        // Tạo reset token sau khi verify OTP thành công
        String resetToken = jwtUtil.generateResetToken(username);

        // Xóa OTP sau khi verify
        user.setOtp(null);
        user.setOtpExpiry(null);
        userService.saveUser(user);

        Map<String, String> response = new HashMap<>();
        response.put("message", "OTP verified successfully");
        response.put("resetToken", resetToken);

        return ResponseEntity.ok(response);
    }


    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String resetToken = request.get("resetToken");
        String newPassword = request.get("newPassword");

        if (resetToken == null || !jwtUtil.validateToken(resetToken)) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid or expired reset token");
        }

        String username = jwtUtil.getUsernameFromToken(resetToken);
        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Cập nhật mật khẩu mới
        user.setPassword(passwordEncoder.encode(newPassword));
        userService.saveUser(user);

        return ResponseEntity.ok("Password reset successfully");
    }


    @GetMapping("/recovery-code")
    public ResponseEntity<?> getRecoveryCode(HttpServletRequest httpRequest) {
        String username = (String) httpRequest.getAttribute("username");

        if (username == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Unauthorized");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Tạo recovery code mới
        String recoveryCode = generateRecoveryCode();
        user.setRecoveryCode(recoveryCode);
        userService.saveUser(user);

        Map<String, String> response = new HashMap<>();
        response.put("recoveryCode", recoveryCode);
        response.put("message", "Save this code in a safe place");

        return ResponseEntity.ok(response);
    }


    @PostMapping("/reset-password-with-code")
    public ResponseEntity<?> resetPasswordWithCode(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String recoveryCode = request.get("recoveryCode");
        String newPassword = request.get("newPassword");

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Kiểm tra recovery code
        if (user.getRecoveryCode() == null || !user.getRecoveryCode().equals(recoveryCode)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Invalid recovery code");
        }

        // Cập nhật mật khẩu
        user.setPassword(passwordEncoder.encode(newPassword));
        // Xóa recovery code sau khi sử dụng (hoặc giữ lại tùy yêu cầu)
        user.setRecoveryCode(null);
        userService.saveUser(user);

        return ResponseEntity.ok("Password reset successfully with recovery code");
    }

    // Helper: Tạo OTP 6 số
    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // 6 chữ số
        return String.valueOf(otp);
    }

    // Helper: Tạo recovery code
    private String generateRecoveryCode() {
        return UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }
}