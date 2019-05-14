package online.kheops.auth_server.util;

import java.security.Principal;

public class TokenPrincipal implements Principal {
    private String name;
    private TokenClientKind clientKind;

    public TokenPrincipal(String name, TokenClientKind clientKind) {
        this.name = name;
        this.clientKind = clientKind;
    }

    @Override
    public String getName() {
        return name;
    }

    public TokenClientKind getClientKind() {
        return clientKind;
    }
}
