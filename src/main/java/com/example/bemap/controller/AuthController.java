package com.example.bemap.controller;

import com.example.bemap.entity.User;
import com.example.bemap.service.UserService;
import com.example.bemap.service.EmailService;
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
    private final EmailService emailService;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthController(UserService userService, JwtUtil jwtUtil, EmailService emailService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userService.existsByUsername(user.getUsername())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Username already exists");
        }

        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Email is required");
        }

        if (!isValidEmail(user.getEmail())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Invalid email format");
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

        // Kiểm tra nếu user bật 2FA
        if (found.isTwoFactorEnabled()) {
            // Tạo OTP 6 số
            String otp = generateOTP();

            // Lưu OTP vào database (thời hạn 5 phút)
            found.setTwoFactorOtp(otp);
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.MINUTE, 5);
            found.setTwoFactorOtpExpiry(cal.getTime());
            userService.saveUser(found);

            // Gửi OTP qua email
            try {
                emailService.sendOTP(found.getEmail(), otp);
            } catch (Exception e) {
                System.err.println("Failed to send 2FA email: " + e.getMessage());
                return ResponseEntity
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to send 2FA code. Please try again later.");
            }

            Map<String, Object> response = new HashMap<>();
            response.put("requires2FA", true);
            response.put("message", "2FA code has been sent to your email");
            response.put("username", found.getUsername());

            return ResponseEntity.ok(response);
        }

        // Nếu không bật 2FA, login bình thường
        String accessToken = jwtUtil.generateAccessToken(found.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(found.getUsername());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<?> verify2FA(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String otp = request.get("otp");

        if (username == null || otp == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Username and OTP are required");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        // Kiểm tra OTP 2FA
        String storedOtp = user.getTwoFactorOtp();
        Date otpExpiry = user.getTwoFactorOtpExpiry();

        if (storedOtp == null || !storedOtp.equals(otp)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Invalid 2FA code");
        }

        if (otpExpiry == null || otpExpiry.before(new Date())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("2FA code expired");
        }

        // Xóa OTP sau khi verify thành công
        user.setTwoFactorOtp(null);
        user.setTwoFactorOtpExpiry(null);
        userService.saveUser(user);

        // Tạo token
        String accessToken = jwtUtil.generateAccessToken(user.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enable2FA(HttpServletRequest httpRequest) {
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

        if (user.isTwoFactorEnabled()) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("2FA is already enabled");
        }

        user.setTwoFactorEnabled(true);
        userService.saveUser(user);

        return ResponseEntity.ok("2FA enabled successfully");
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disable2FA(@RequestBody Map<String, String> request,
                                        HttpServletRequest httpRequest) {
        String username = (String) httpRequest.getAttribute("username");

        if (username == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Unauthorized");
        }

        String password = request.get("password");

        if (password == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Password is required to disable 2FA");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        if (!user.isTwoFactorEnabled()) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("2FA is not enabled");
        }

        // Xác thực mật khẩu trước khi tắt 2FA
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Incorrect password");
        }

        user.setTwoFactorEnabled(false);
        user.setTwoFactorOtp(null);
        user.setTwoFactorOtpExpiry(null);
        userService.saveUser(user);

        return ResponseEntity.ok("2FA disabled successfully");
    }

    @GetMapping("/2fa-status")
    public ResponseEntity<?> get2FAStatus(HttpServletRequest httpRequest) {
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

        Map<String, Boolean> response = new HashMap<>();
        response.put("twoFactorEnabled", user.isTwoFactorEnabled());

        return ResponseEntity.ok(response);
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

        if (oldPassword == null || newPassword == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Old password and new password are required");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

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

        if (username == null || email == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Username and email are required");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

        if (user.getEmail() == null || !user.getEmail().equals(email)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Email does not match");
        }

        String otp = generateOTP();

        user.setOtp(otp);
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, 5);
        user.setOtpExpiry(cal.getTime());
        userService.saveUser(user);

        try {
            emailService.sendOTP(user.getEmail(), otp);
        } catch (Exception e) {
            System.err.println("Failed to send email: " + e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to send email. Please try again later.");
        }

        Map<String, String> response = new HashMap<>();
        response.put("message", "OTP has been sent to your email");
        response.put("expiresIn", "5 minutes");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String otp = request.get("otp");

        if (username == null || otp == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Username and OTP are required");
        }

        User user = userService.findByUsername(username);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }

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

        String resetToken = jwtUtil.generateResetToken(username);

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

        if (resetToken == null || newPassword == null) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body("Reset token and new password are required");
        }

        if (!jwtUtil.validateToken(resetToken)) {
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

        user.setPassword(passwordEncoder.encode(newPassword));
        userService.saveUser(user);

        return ResponseEntity.ok("Password reset successfully");
    }

    // Helper methods
    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        return email.matches(emailRegex);
    }
}