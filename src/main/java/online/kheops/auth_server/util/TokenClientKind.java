package online.kheops.auth_server.util;

public enum TokenClientKind {
    REPORT_PROVIDER("report_provider_client"),
    INTERNAL("internal_client"),
    PUBLIC("public_client"),
    INVALID("invalid");

    private String roleString;

    TokenClientKind(String roleString) {
        this.roleString = roleString;
    }

    public String getRoleString() {
        if (this == INVALID) {
            throw new IllegalStateException("INVALID ClientKind  does not have a role");
        }
        return roleString;
    }
}
