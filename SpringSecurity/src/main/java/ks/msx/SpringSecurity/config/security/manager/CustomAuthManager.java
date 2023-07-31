package ks.msx.SpringSecurity.config.security.manager;

import ks.msx.SpringSecurity.config.security.provider.CustomAuthProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CustomAuthManager implements AuthenticationManager {
    private final CustomAuthProvider customAuthProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (customAuthProvider.supports(authentication.getClass())){
            return customAuthProvider.authenticate(authentication);
        }
        throw new BadCredentialsException("Auth Provider Exception");
    }
}
