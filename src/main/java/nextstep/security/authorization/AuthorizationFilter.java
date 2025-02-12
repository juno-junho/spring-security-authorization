package nextstep.security.authorization;

import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Set;

public class AuthorizationFilter extends OncePerRequestFilter {

    private static final List<String> DEFAULT_REQUEST_URI = List.of("/members", "/members/me", "/search", "/login");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            if (!checkAuthorization(request)) {
                throw new ForbiddenException();
            }
        } catch (UnauthorizedException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        catch (ForbiddenException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        filterChain.doFilter(request, response);
    }

    // manager의 역할 이게 authorization 역할인지 아닌지
    private boolean checkAuthorization(HttpServletRequest request) {
        String requestURI = request.getRequestURI();

        if (!DEFAULT_REQUEST_URI.contains(requestURI)) {
            return false;
        }

        if (requestURI.equals("/login") || requestURI.equals("/search")) { // /search 경로와 /login는 누구나 접근이 가능
            return true;
        }

        // 인증 진행
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UnauthorizedException();
        }

        if(requestURI.equals("/members/me")) {
            return true;
        }

        // 인가 진행
        Set<String> authorities = authentication.getAuthorities();
        if (requestURI.equals("/members") ){
            if (authorities.contains("ADMIN")) {
                return true;
            }
        }
        throw new ForbiddenException();
    }

}
