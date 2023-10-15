package br.com.gabrielfsdev.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.gabrielfsdev.todolist.user.UserModel;
import br.com.gabrielfsdev.todolist.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Objects;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    UserRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");

        String user = authorization.substring("Basic".length()).trim();

        byte[] decoded = Base64.getDecoder().decode(user);

        var userAndPassword = new String(decoded);

        String[] split = userAndPassword.split(":");

        String username = split[0];
        String password = split[1];

        UserModel byusername = repository.findByusername(username);

        if (Objects.isNull(byusername)) {
            response.sendError(401);
        } else {
            var verify = BCrypt.verifyer().verify(password.toCharArray(), byusername.getPassword());
            if (verify.verified) {
                filterChain.doFilter(request, response);
            } else {
                response.sendError(401);
            }
        }
    }
}
