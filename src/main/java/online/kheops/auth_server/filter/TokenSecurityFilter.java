package online.kheops.auth_server.filter;

import online.kheops.auth_server.annotation.TokenSecurity;
import online.kheops.auth_server.util.TokenClientAuthentication;
import online.kheops.auth_server.util.TokenErrorResponse;
import online.kheops.auth_server.util.TokenPrincipal;
import org.glassfish.jersey.server.ContainerRequest;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Principal;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

@TokenSecurity
@Provider
@Priority(Priorities.AUTHENTICATION)
public class TokenSecurityFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        final ContainerRequest containerRequest;
        if (requestContext instanceof ContainerRequest) {
            containerRequest = (ContainerRequest) requestContext;
        } else {
            throw new IllegalStateException("requestContext is not a ContainerRequest");
        }

        final Form form;
        final MultivaluedMap<String, String> requestHeaders;
        try {
            containerRequest.bufferEntity();
            form = containerRequest.readEntity(Form.class);
            requestHeaders = containerRequest.getRequestHeaders();
        } catch (ProcessingException e) {
            throw new IOException(e);
        }

        TokenClientAuthentication authenticationType = TokenClientAuthentication.getTokenClientAuthentication(requestHeaders, form);
        if (authenticationType == TokenClientAuthentication.INVALID) {
            requestContext.abortWith(Response.status(BAD_REQUEST).entity(new TokenErrorResponse(TokenErrorResponse.Error.INVALID_REQUEST)).build());
            return;
        }

        final TokenPrincipal principal = authenticationType.getPrincipal(requestHeaders, form);
        if (principal == null) {
            requestContext.abortWith(Response.status(BAD_REQUEST).entity(new TokenErrorResponse(TokenErrorResponse.Error.INVALID_CLIENT)).build());
            return;
        }

        final boolean isSecured = requestContext.getSecurityContext().isSecure();

        requestContext.setSecurityContext(new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return principal;
            }

            @Override
            public boolean isUserInRole(String role) {
                return role.equals(principal.getClientKind().getRoleString());
            }

            @Override
            public boolean isSecure() {
                return isSecured;
            }

            @Override
            public String getAuthenticationScheme() {
                return authenticationType.getSchemeString();
            }
        });
    }
}
