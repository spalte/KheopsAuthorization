package online.kheops.auth_server.util;

import java.security.Principal;
import java.util.Objects;

public class TokenPrincipal implements Principal {
    private String name;
    private TokenClientKind clientKind;

    public TokenPrincipal(String name, TokenClientKind clientKind) {
        this.name = Objects.requireNonNull(name);
        this.clientKind = Objects.requireNonNull(clientKind);
    }

    public TokenPrincipal(Principal principal, TokenClientKind clientKind) {
        this.name = Objects.requireNonNull(principal).getName();
        this.clientKind = Objects.requireNonNull(clientKind);
    }

    @Override
    public String getName() {
        return name;
    }

    public TokenClientKind getClientKind() {
        return clientKind;
    }
}
