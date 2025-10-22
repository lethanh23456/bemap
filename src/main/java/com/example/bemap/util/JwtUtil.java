package com.example.bemap.util;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;

@Component
public class JwtUtil {


    private final String SECRET_KEY = "NSOdxOzJ4UaA7e2gsv1IS4IGVOvZap62ETKtdMDTBMeUB6HCJnpi5sDTchN5aKGY";


    private final long EXPIRATION = 86400000; // 86400000 ms


    public String generateToken(String username) {
        try {
            // Tạo signer với secret key
            JWSSigner signer = new MACSigner(SECRET_KEY.getBytes());

            // Tạo claims (thông tin trong token)
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(username)
                    .issuer("nro-backend")
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRATION))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    claimsSet
            );


            signedJWT.sign(signer);

            return signedJWT.serialize();

        } catch (JOSEException e) {
            throw new RuntimeException("Không thể tạo token: " + e.getMessage());
        }
    }


    public String getUsernameFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            throw new RuntimeException("Token không hợp lệ: " + e.getMessage());
        }
    }


    public boolean validateToken(String token) {
        try {

            SignedJWT signedJWT = SignedJWT.parse(token);

            JWSVerifier verifier = new MACVerifier(SECRET_KEY.getBytes());


            if (!signedJWT.verify(verifier)) {
                return false;
            }

            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            return !expirationTime.before(new Date());

        } catch (Exception e) {
            return false;
        }
    }
}