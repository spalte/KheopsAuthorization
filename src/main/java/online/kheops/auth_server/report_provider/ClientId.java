package online.kheops.auth_server.report_provider;

import java.security.SecureRandom;
import java.util.Random;

public class ClientId {

    private static final String CLIENT_ID_DICT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private static final int CLIENT_ID_LENGTH = 22;
    public static final String CLIENT_ID_PATTERN = "[A-Za-z0-9]{" + CLIENT_ID_LENGTH + "}";

    private final String id;

    private static final Random rdm = new SecureRandom();

    public ClientId() {
        final StringBuilder secretBuilder = new StringBuilder();
        while (secretBuilder.length() < CLIENT_ID_LENGTH) {
            int index = rdm.nextInt(CLIENT_ID_DICT.length());
            secretBuilder.append(CLIENT_ID_DICT.charAt(index));
        }
        id = secretBuilder.toString();
    }

    public String getClientId() { return id; }
}
