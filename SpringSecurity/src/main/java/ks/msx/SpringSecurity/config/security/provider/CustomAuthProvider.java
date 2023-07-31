package ks.msx.SpringSecurity.config.security.provider;

import ks.msx.SpringSecurity.config.security.auth.CustomAuth;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthProvider implements AuthenticationProvider {
    @Value("${key}")
    private String key;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuth ca = (CustomAuth) authentication;
        String headerKey = ca.getKey();
        if(key.equals(headerKey)){
           return new CustomAuth(true, null);
        }
        throw new BadCredentialsException("Bad Credentials Exception");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuth.class.equals(authentication);
    }
}
