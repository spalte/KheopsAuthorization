package online.kheops.auth_server.resource;

import online.kheops.auth_server.EntityManagerListener;
import online.kheops.auth_server.album.AlbumId;
import online.kheops.auth_server.album.AlbumNotFoundException;
import online.kheops.auth_server.annotation.*;
import online.kheops.auth_server.accesstoken.*;
import online.kheops.auth_server.entity.Album;
import online.kheops.auth_server.entity.ReportProvider;
import online.kheops.auth_server.entity.User;
import online.kheops.auth_server.report_provider.*;
import online.kheops.auth_server.principal.KheopsPrincipalInterface;
import online.kheops.auth_server.token.ReportProviderAccessTokenGenerator;
import online.kheops.auth_server.token.ReportProviderAuthCodeGenerator;
import online.kheops.auth_server.user.UserNotFoundException;
import online.kheops.auth_server.user.AlbumUserPermissions;
import online.kheops.auth_server.util.PairListXTotalCount;
import online.kheops.auth_server.util.KheopsLogBuilder.ActionType;
import online.kheops.auth_server.util.KheopsLogBuilder;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.NoResultException;
import javax.servlet.ServletContext;
import javax.validation.constraints.Min;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.logging.Level.INFO;
import static javax.ws.rs.core.Response.Status.*;
import static online.kheops.auth_server.album.Albums.getAlbum;
import static online.kheops.auth_server.report_provider.ReportProviderQueries.getReportProviderWithClientId;
import static online.kheops.auth_server.report_provider.ReportProviders.*;
import static online.kheops.auth_server.study.Studies.canAccessStudy;
import static online.kheops.auth_server.user.AlbumUserPermissions.ADD_SERIES;
import static online.kheops.auth_server.user.Users.getOrCreateUser;
import static online.kheops.auth_server.util.Consts.*;
import static online.kheops.auth_server.util.Consts.QUERY_PARAMETER_OFFSET;
import static online.kheops.auth_server.util.HttpHeaders.X_TOTAL_COUNT;
import static online.kheops.auth_server.util.Tools.checkValidUID;


@Path("/")
public class ReportProviderResource {
    private static final Logger LOG = Logger.getLogger(ReportProviderResource.class.getName());

    private static final String HOST_ROOT_PARAMETER = "online.kheops.root.uri";

    @Context
    private UriInfo uriInfo;

    @Context
    private SecurityContext securityContext;

    @Context
    ServletContext context;

    @POST
    @Secured
    @UserAccessSecured
    @AlbumAccessSecured
    @AlbumPermissionSecured(AlbumUserPermissions.MANAGE_DICOM_SR)
    @Path("albums/{"+ALBUM+":"+ AlbumId.ID_PATTERN+"}/reportproviders")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response newReportProvider(@SuppressWarnings("RSReferenceInspection") @PathParam(ALBUM) String albumId,
                            @FormParam("url") final String url,
                            @FormParam("name") final String name) {

        if (name == null || name.isEmpty()) {
            return Response.status(BAD_REQUEST).entity("'name' formparam must be set").build();
        }

        if (url == null || url.isEmpty()) {
            return Response.status(BAD_REQUEST).entity("'url' formparam must be set").build();
        } else if ( !isValidConfigUrl(url)) {
            return Response.status(BAD_REQUEST).entity("'url' formparam is not valid").build();
        }

        final KheopsPrincipalInterface kheopsPrincipal = ((KheopsPrincipalInterface)securityContext.getUserPrincipal());

        final ReportProviderResponse dicomSrResponse;
        try {
            dicomSrResponse = ReportProviders.newReportProvider(kheopsPrincipal.getUser(), albumId, name, url, kheopsPrincipal.getKheopsLogBuilder());
        } catch (AlbumNotFoundException e) {
            return Response.status(NOT_FOUND).build();
        }

        return Response.status(CREATED).entity(dicomSrResponse).build();
    }

    @POST
    @Path("report")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response newReport(@FormParam("access_token") final String accessToken,
                              @FormParam("client_id") final String clientId,
                              @FormParam("studyUID") List<String> studyInstanceUID) {//Edit UidValidator for work with @FormParam

        if (studyInstanceUID == null || studyInstanceUID.isEmpty()) {
            return Response.status(BAD_REQUEST).entity(StudyInstanceUID +" param must be set").build();
        }

        for (String uid: studyInstanceUID) {
            if (!checkValidUID(uid)) {
                return Response.status(BAD_REQUEST).entity(uid + "is not a valid uid").build();
            }
        }

        final AccessToken assertion;
        try {
            assertion = AccessTokenVerifier.authenticateAccessToken(context, accessToken);
        } catch (AccessTokenVerificationException e) {
            LOG.log(Level.WARNING, "Error validating a token", e);
            return Response.status(UNAUTHORIZED).entity("error with the access_token").build();
        } catch (DownloadKeyException e) {
            LOG.log(Level.SEVERE, "Error downloading the public key", e);
            return Response.status(BAD_GATEWAY).entity("Error downloading the public key").build();
        }

        try {
            getOrCreateUser(assertion.getSub());
        } catch (UserNotFoundException e) {
            LOG.log(Level.WARNING, "User not found", e);
            return Response.status(UNAUTHORIZED).build();
        }

        //vérifier la permission de créer report_provider_code (user) pas capability token
        if (! (assertion.getTokenType() == AccessToken.TokenType.KEYCLOAK_TOKEN  ||
                assertion.getTokenType() == AccessToken.TokenType.SUPER_USER_TOKEN)) {

            return Response.status(FORBIDDEN).build();
        }

        final User callingUser;
        try {
            callingUser = getOrCreateUser(assertion.getSub());
        } catch (UserNotFoundException e) {
            LOG.log(Level.WARNING, "User not found", e);
            return Response.status(UNAUTHORIZED).entity("User not found").build();
        }

        //vérifier l'acces a l'album
        final KheopsPrincipalInterface principal = assertion.newPrincipal(context, callingUser);

        final EntityManager em = EntityManagerListener.createEntityManager();
        final EntityTransaction tx = em.getTransaction();

        final ReportProvider reportProvider;
        final String albumId;
        try {
            tx.begin();
            reportProvider = getReportProviderWithClientId(clientId, em);
            albumId = reportProvider.getAlbum().getId();
        } catch (NoResultException e) {
            LOG.log(Level.WARNING, "Report provider with clientId: " + clientId + "not found", e);
            return Response.status(NOT_FOUND).entity("Report provider with clientId: " + clientId + "not found").build();
        } finally {
            if (tx.isActive()) {
                tx.rollback();
            }
            em.close();
        }

        final Album album;
        try {
            if (! (principal.hasUserAccess() && principal.hasAlbumAccess(albumId))) {
                return Response.status(FORBIDDEN).build();
            }

            album = getAlbum(albumId);
            for (String uid : studyInstanceUID) {
                if (!canAccessStudy(album, uid)) {
                    return Response.status(NOT_FOUND).entity("Study uid: " + uid + "not found").build();
                }
            }
        } catch (AlbumNotFoundException e) {
            return Response.status(NOT_FOUND).entity(e.getMessage()).build();
        }

        final String responseType;
        try {
            responseType = getResponseType(reportProvider);
        } catch (ReportProviderUriNotValidException e) {
            return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
        }

        final String kheopsConfigUrl = getHostRoot() + "/api/reportproviders/" + clientId + "/configuration";
        if (responseType.equals("code")) {
            final String token = ReportProviderAuthCodeGenerator.createGenerator(context)
                    .withClientId(reportProvider.getClientId())
                    .withStudyInstanceUIDs(studyInstanceUID)
                    .withSubject(assertion.getSub())
                    .generate(600);

            try {
                final String confUri = URLEncoder.encode(kheopsConfigUrl, UTF_8.toString());
                final UriBuilder reportProviderUrlBuilder = UriBuilder.fromUri(getRedirectUri(reportProvider))
                        .queryParam("code", token)
                        .queryParam("conf_uri", confUri)
                        .queryParam("client_id", reportProvider.getClientId());

                for (String uid : studyInstanceUID) {
                    reportProviderUrlBuilder.queryParam("studyUID", URLEncoder.encode(uid, UTF_8.toString()));
                }

                final String reportProviderUrl = reportProviderUrlBuilder.toString();

                return Response.status(SEE_OTHER).header("Location", reportProviderUrl).build();
            } catch (ReportProviderUriNotValidException e) {
                return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
            } catch (UnsupportedEncodingException e) {
                return Response.status(FORBIDDEN).entity("ERROR").build();
            }
        } else if (responseType.equals("token")) {
            try {
                final boolean userHasWriteAccess = principal.hasAlbumPermission(ADD_SERIES, albumId);
                final String token = ReportProviderAccessTokenGenerator.createGenerator(context)
                        .withClientId(clientId)
                        .withScope(userHasWriteAccess ? "read write" : "read")
                        .withStudyInstanceUIDs(studyInstanceUID)
                        .withSubject(assertion.getSub())
                        .generate(3600);

                final String confUri = URLEncoder.encode(kheopsConfigUrl, UTF_8.toString());

                final String reportProviderUrl = UriBuilder.fromUri(getRedirectUri(reportProvider))
                        .fragment("access_token=" + token +
                                "&token_type=" + "Bearer" +
                                "&expires_in=3600" +
                                "&scope=" + (userHasWriteAccess ? "read%20write" : "read") +
                                "&client_id=" + clientId +
                                "&conf_uri=" + confUri +
                                studyInstanceUID.stream()
                                        .map(uid -> "&study_uid="+uid)
                                        .collect(Collectors.joining()))
                        .toString();

                KheopsLogBuilder kheopsLogBuilder = principal.getKheopsLogBuilder()
                        .action(ActionType.NEW_REPORT)
                        .album(albumId)
                        .clientID(clientId);
                for (String studyUID:studyInstanceUID) {
                    kheopsLogBuilder.study(studyUID);
                }
                kheopsLogBuilder.log();

                return Response.status(SEE_OTHER).header("Location", reportProviderUrl).build();
            } catch (AlbumNotFoundException e) {
                throw new IllegalStateException("Album just found, how could we not have it now", e);
            } catch (ReportProviderUriNotValidException e) {
                return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
            } catch (UnsupportedEncodingException e) {
                return Response.status(FORBIDDEN).entity("ERROR").build();
            }
        } else {
            return Response.status(BAD_REQUEST).entity("bad response type").build();
        }
    }

    @GET
    @Path("reportproviders/{clientId:"+ ClientId.CLIENT_ID_PATTERN+"}/configuration")
    @Produces(MediaType.APPLICATION_JSON)
    public Response configuration(@SuppressWarnings("RSReferenceInspection") @PathParam("clientId") String clientId) {

        final ConfigurationResponse configurationResponse;
        try {
            configurationResponse = new ConfigurationResponse(clientId, getHostRoot());
        } catch (ClientIdNotFoundException e) {
            return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
        }
        new KheopsLogBuilder().action(ActionType.REPORT_PROVIDER_CONFIGURATION)
                .clientID(clientId)
                .log();
        return  Response.status(OK).entity(configurationResponse).build();
    }

    @GET
    @Secured
    @UserAccessSecured
    @AlbumAccessSecured
    @AlbumPermissionSecured(AlbumUserPermissions.GET_DICOM_SR)
    @Path("albums/{"+ALBUM+":"+ AlbumId.ID_PATTERN+"}/reportproviders")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllReportProviders(@SuppressWarnings("RSReferenceInspection") @PathParam(ALBUM) String albumId,
                                          @QueryParam(QUERY_PARAMETER_LIMIT) @Min(0) @DefaultValue(""+Integer.MAX_VALUE) Integer limit,
                                          @QueryParam(QUERY_PARAMETER_OFFSET) @Min(0) @DefaultValue("0") Integer offset) {

        final PairListXTotalCount<ReportProviderResponse> pair;

        pair = ReportProviders.getReportProviders(albumId, limit, offset, ((KheopsPrincipalInterface)securityContext.getUserPrincipal()).getKheopsLogBuilder());

        final GenericEntity<List<ReportProviderResponse>> genericReportProvidersResponsesList = new GenericEntity<List<ReportProviderResponse>>(pair.getAttributesList()) {};
        return  Response.status(OK).entity(genericReportProvidersResponsesList).header(X_TOTAL_COUNT, pair.getXTotalCount()).build();
    }

    @GET
    @Secured
    @UserAccessSecured
    @AlbumAccessSecured
    @AlbumPermissionSecured(AlbumUserPermissions.GET_DICOM_SR)
    @Path("albums/{"+ALBUM+":"+ AlbumId.ID_PATTERN+"}/reportproviders/{clientId:"+ ClientId.CLIENT_ID_PATTERN+"}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getReportProviders(@SuppressWarnings("RSReferenceInspection") @PathParam(ALBUM) String albumId,
                                       @SuppressWarnings("RSReferenceInspection") @PathParam("clientId") String clientId) {

        final ReportProviderResponse reportProvider;
        try {
            reportProvider = getReportProvider(albumId, clientId, ((KheopsPrincipalInterface)securityContext.getUserPrincipal()).getKheopsLogBuilder());
        } catch (ClientIdNotFoundException e) {
            return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
        }

        return  Response.status(OK).entity(reportProvider).build();
    }

    @DELETE
    @Secured
    @UserAccessSecured
    @AlbumAccessSecured
    @AlbumPermissionSecured(AlbumUserPermissions.MANAGE_DICOM_SR)
    @Path("albums/{"+ALBUM+":"+ AlbumId.ID_PATTERN+"}/reportproviders/{clientId:"+ ClientId.CLIENT_ID_PATTERN+"}")
    public Response deleteReportProviders(@SuppressWarnings("RSReferenceInspection") @PathParam(ALBUM) String albumId,
                                          @SuppressWarnings("RSReferenceInspection") @PathParam("clientId") String clientId) {

        final KheopsPrincipalInterface kheopsPrincipal = ((KheopsPrincipalInterface)securityContext.getUserPrincipal());
        final User callingUser = kheopsPrincipal.getUser();
        try {
            deleteReportProvider(callingUser, albumId, clientId, kheopsPrincipal.getKheopsLogBuilder());
        } catch (ClientIdNotFoundException e) {
            return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
        } catch (AlbumNotFoundException e) {
            return Response.status(NOT_FOUND).entity(e.getMessage()).build();
        }

        return  Response.status(NO_CONTENT).build();
    }

    @PATCH
    @Secured
    @UserAccessSecured
    @AlbumAccessSecured
    @AlbumPermissionSecured(AlbumUserPermissions.MANAGE_DICOM_SR)
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Path("albums/{"+ALBUM+":"+ AlbumId.ID_PATTERN+"}/reportproviders/{clientId:"+ ClientId.CLIENT_ID_PATTERN+"}")
    public Response editReportProviders(@SuppressWarnings("RSReferenceInspection") @PathParam(ALBUM) String albumId,
                                        @SuppressWarnings("RSReferenceInspection") @PathParam("clientId") String clientId,
                                        @FormParam("url") final String url,
                                        @FormParam("name") final String name,
                                        @FormParam("new_client_id") final boolean newClientId) {


        if(!(url == null || url.isEmpty() )) {
            if(!isValidConfigUrl(url)) {
                return Response.status(BAD_REQUEST).entity("url not valid").build();
            }
        }

        final KheopsPrincipalInterface kheopsPrincipal = ((KheopsPrincipalInterface)securityContext.getUserPrincipal());
        final User callingUser = kheopsPrincipal.getUser();

        final ReportProviderResponse reportProvider;
        try {
            reportProvider = editReportProvider(callingUser, albumId, clientId, url, name, newClientId, kheopsPrincipal.getKheopsLogBuilder());
        } catch (ClientIdNotFoundException e) {
            return Response.status(BAD_REQUEST).entity(e.getMessage()).build();
        } catch (AlbumNotFoundException e) {
            return Response.status(NOT_FOUND).entity(e.getMessage()).build();
        }

        return  Response.status(OK).entity(reportProvider).build();
    }

    @POST
    @Secured
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Path("reportproviders/metadata")
    public Response testUri(@FormParam("url") final String url) {

        if (url == null || url.isEmpty()) {
            return Response.status(BAD_REQUEST).entity("Missing formParam 'url'").build();
        }

        ReportProviderClientMetadata clientMetadataResponse = new ReportProviderClientMetadata();

        try {
            clientMetadataResponse = getClientMetadata(url);
            clientMetadataResponse.setValid(true);
        } catch (ReportProviderUriNotValidException e) {
            LOG.log(INFO, "error validating the configuration url", e);
            clientMetadataResponse.setValid(false);
            clientMetadataResponse.setErrorDescription(e.getMessage());
        }

        ((KheopsPrincipalInterface)securityContext.getUserPrincipal()).getKheopsLogBuilder()
                .action(ActionType.REPORT_PROVIDER_METADATA)
                .log();
        return  Response.status(OK).entity(clientMetadataResponse).build();
    }

    private String getHostRoot() {
        return context.getInitParameter(HOST_ROOT_PARAMETER);
    }
}
