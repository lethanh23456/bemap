package com.example.bemap.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendOTP(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("your-email@gmail.com"); // Thay bằng email của bạn
        message.setTo(toEmail);
        message.setSubject("Your OTP Code - BeMap");
        message.setText(
                "Hello,\n\n" +
                        "Your OTP code is: " + otp + "\n\n" +
                        "This code will expire in 5 minutes.\n\n" +
                        "If you didn't request this, please ignore this email.\n\n" +
                        "Best regards,\n" +
                        "BeMap Team"
        );

        mailSender.send(message);
    }
}