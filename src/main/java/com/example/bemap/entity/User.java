package com.example.bemap.entity;

import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = true)
    private String otp;

    @Column(nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
    private Date otpExpiry;

    // 2FA fields
    @Column(nullable = false)
    private boolean twoFactorEnabled = false;

    @Column(nullable = true)
    private String twoFactorOtp;

    @Column(nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
    private Date twoFactorOtpExpiry;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getOtp() { return otp; }
    public void setOtp(String otp) { this.otp = otp; }

    public Date getOtpExpiry() { return otpExpiry; }
    public void setOtpExpiry(Date otpExpiry) { this.otpExpiry = otpExpiry; }

    public boolean isTwoFactorEnabled() { return twoFactorEnabled; }
    public void setTwoFactorEnabled(boolean twoFactorEnabled) {
        this.twoFactorEnabled = twoFactorEnabled;
    }

    public String getTwoFactorOtp() { return twoFactorOtp; }
    public void setTwoFactorOtp(String twoFactorOtp) {
        this.twoFactorOtp = twoFactorOtp;
    }

    public Date getTwoFactorOtpExpiry() { return twoFactorOtpExpiry; }
    public void setTwoFactorOtpExpiry(Date twoFactorOtpExpiry) {
        this.twoFactorOtpExpiry = twoFactorOtpExpiry;
    }
}