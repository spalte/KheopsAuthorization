/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated;


import javax.annotation.Generated;

import online.kheops.auth_server.generated.tables.Capabilities;
import online.kheops.auth_server.generated.tables.Series;
import online.kheops.auth_server.generated.tables.Studies;
import online.kheops.auth_server.generated.tables.UserSeries;
import online.kheops.auth_server.generated.tables.Users;
import online.kheops.auth_server.generated.tables.records.CapabilitiesRecord;
import online.kheops.auth_server.generated.tables.records.SeriesRecord;
import online.kheops.auth_server.generated.tables.records.StudiesRecord;
import online.kheops.auth_server.generated.tables.records.UserSeriesRecord;
import online.kheops.auth_server.generated.tables.records.UsersRecord;

import org.jooq.ForeignKey;
import org.jooq.Identity;
import org.jooq.UniqueKey;
import org.jooq.impl.Internal;


/**
 * A class modelling foreign key relationships and constraints of tables of 
 * the <code>kheops</code> schema.
 */
@Generated(
    value = {
        "http://www.jooq.org",
        "jOOQ version:3.11.2"
    },
    comments = "This class is generated by jOOQ"
)
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class Keys {

    // -------------------------------------------------------------------------
    // IDENTITY definitions
    // -------------------------------------------------------------------------

    public static final Identity<CapabilitiesRecord, Long> IDENTITY_CAPABILITIES = Identities0.IDENTITY_CAPABILITIES;
    public static final Identity<SeriesRecord, Long> IDENTITY_SERIES = Identities0.IDENTITY_SERIES;
    public static final Identity<StudiesRecord, Long> IDENTITY_STUDIES = Identities0.IDENTITY_STUDIES;
    public static final Identity<UsersRecord, Long> IDENTITY_USERS = Identities0.IDENTITY_USERS;

    // -------------------------------------------------------------------------
    // UNIQUE and PRIMARY KEY definitions
    // -------------------------------------------------------------------------

    public static final UniqueKey<CapabilitiesRecord> KEY_CAPABILITIES_PRIMARY = UniqueKeys0.KEY_CAPABILITIES_PRIMARY;
    public static final UniqueKey<CapabilitiesRecord> KEY_CAPABILITIES_SECRET_UNIQUE = UniqueKeys0.KEY_CAPABILITIES_SECRET_UNIQUE;
    public static final UniqueKey<SeriesRecord> KEY_SERIES_PRIMARY = UniqueKeys0.KEY_SERIES_PRIMARY;
    public static final UniqueKey<SeriesRecord> KEY_SERIES_SERIES_UID_UNIQUE = UniqueKeys0.KEY_SERIES_SERIES_UID_UNIQUE;
    public static final UniqueKey<StudiesRecord> KEY_STUDIES_PRIMARY = UniqueKeys0.KEY_STUDIES_PRIMARY;
    public static final UniqueKey<StudiesRecord> KEY_STUDIES_STUDY_UID_UNIQUE = UniqueKeys0.KEY_STUDIES_STUDY_UID_UNIQUE;
    public static final UniqueKey<UsersRecord> KEY_USERS_PRIMARY = UniqueKeys0.KEY_USERS_PRIMARY;
    public static final UniqueKey<UsersRecord> KEY_USERS_GOOGLE_ID_UNIQUE = UniqueKeys0.KEY_USERS_GOOGLE_ID_UNIQUE;
    public static final UniqueKey<UsersRecord> KEY_USERS_GOOGLE_EMAIL_UNIQUE = UniqueKeys0.KEY_USERS_GOOGLE_EMAIL_UNIQUE;
    public static final UniqueKey<UserSeriesRecord> KEY_USER_SERIES_PRIMARY = UniqueKeys0.KEY_USER_SERIES_PRIMARY;

    // -------------------------------------------------------------------------
    // FOREIGN KEY definitions
    // -------------------------------------------------------------------------

    public static final ForeignKey<CapabilitiesRecord, UsersRecord> CAPABILITIES_IBFK_1 = ForeignKeys0.CAPABILITIES_IBFK_1;
    public static final ForeignKey<SeriesRecord, StudiesRecord> SERIES_IBFK_1 = ForeignKeys0.SERIES_IBFK_1;
    public static final ForeignKey<UserSeriesRecord, UsersRecord> USER_SERIES_IBFK_1 = ForeignKeys0.USER_SERIES_IBFK_1;
    public static final ForeignKey<UserSeriesRecord, SeriesRecord> USER_SERIES_IBFK_2 = ForeignKeys0.USER_SERIES_IBFK_2;

    // -------------------------------------------------------------------------
    // [#1459] distribute members to avoid static initialisers > 64kb
    // -------------------------------------------------------------------------

    private static class Identities0 {
        public static Identity<CapabilitiesRecord, Long> IDENTITY_CAPABILITIES = Internal.createIdentity(Capabilities.CAPABILITIES, Capabilities.CAPABILITIES.PK);
        public static Identity<SeriesRecord, Long> IDENTITY_SERIES = Internal.createIdentity(Series.SERIES, Series.SERIES.PK);
        public static Identity<StudiesRecord, Long> IDENTITY_STUDIES = Internal.createIdentity(Studies.STUDIES, Studies.STUDIES.PK);
        public static Identity<UsersRecord, Long> IDENTITY_USERS = Internal.createIdentity(Users.USERS, Users.USERS.PK);
    }

    private static class UniqueKeys0 {
        public static final UniqueKey<CapabilitiesRecord> KEY_CAPABILITIES_PRIMARY = Internal.createUniqueKey(Capabilities.CAPABILITIES, "KEY_capabilities_PRIMARY", Capabilities.CAPABILITIES.PK);
        public static final UniqueKey<CapabilitiesRecord> KEY_CAPABILITIES_SECRET_UNIQUE = Internal.createUniqueKey(Capabilities.CAPABILITIES, "KEY_capabilities_secret_unique", Capabilities.CAPABILITIES.SECRET);
        public static final UniqueKey<SeriesRecord> KEY_SERIES_PRIMARY = Internal.createUniqueKey(Series.SERIES, "KEY_series_PRIMARY", Series.SERIES.PK);
        public static final UniqueKey<SeriesRecord> KEY_SERIES_SERIES_UID_UNIQUE = Internal.createUniqueKey(Series.SERIES, "KEY_series_series_uid_unique", Series.SERIES.SERIES_UID);
        public static final UniqueKey<StudiesRecord> KEY_STUDIES_PRIMARY = Internal.createUniqueKey(Studies.STUDIES, "KEY_studies_PRIMARY", Studies.STUDIES.PK);
        public static final UniqueKey<StudiesRecord> KEY_STUDIES_STUDY_UID_UNIQUE = Internal.createUniqueKey(Studies.STUDIES, "KEY_studies_study_uid_unique", Studies.STUDIES.STUDY_UID);
        public static final UniqueKey<UsersRecord> KEY_USERS_PRIMARY = Internal.createUniqueKey(Users.USERS, "KEY_users_PRIMARY", Users.USERS.PK);
        public static final UniqueKey<UsersRecord> KEY_USERS_GOOGLE_ID_UNIQUE = Internal.createUniqueKey(Users.USERS, "KEY_users_google_id_unique", Users.USERS.GOOGLE_ID);
        public static final UniqueKey<UsersRecord> KEY_USERS_GOOGLE_EMAIL_UNIQUE = Internal.createUniqueKey(Users.USERS, "KEY_users_google_email_unique", Users.USERS.GOOGLE_EMAIL);
        public static final UniqueKey<UserSeriesRecord> KEY_USER_SERIES_PRIMARY = Internal.createUniqueKey(UserSeries.USER_SERIES, "KEY_user_series_PRIMARY", UserSeries.USER_SERIES.USER_FK, UserSeries.USER_SERIES.SERIES_FK);
    }

    private static class ForeignKeys0 {
        public static final ForeignKey<CapabilitiesRecord, UsersRecord> CAPABILITIES_IBFK_1 = Internal.createForeignKey(online.kheops.auth_server.generated.Keys.KEY_USERS_PRIMARY, Capabilities.CAPABILITIES, "capabilities_ibfk_1", Capabilities.CAPABILITIES.USER_FK);
        public static final ForeignKey<SeriesRecord, StudiesRecord> SERIES_IBFK_1 = Internal.createForeignKey(online.kheops.auth_server.generated.Keys.KEY_STUDIES_PRIMARY, Series.SERIES, "series_ibfk_1", Series.SERIES.STUDY_FK);
        public static final ForeignKey<UserSeriesRecord, UsersRecord> USER_SERIES_IBFK_1 = Internal.createForeignKey(online.kheops.auth_server.generated.Keys.KEY_USERS_PRIMARY, UserSeries.USER_SERIES, "user_series_ibfk_1", UserSeries.USER_SERIES.USER_FK);
        public static final ForeignKey<UserSeriesRecord, SeriesRecord> USER_SERIES_IBFK_2 = Internal.createForeignKey(online.kheops.auth_server.generated.Keys.KEY_SERIES_PRIMARY, UserSeries.USER_SERIES, "user_series_ibfk_2", UserSeries.USER_SERIES.SERIES_FK);
    }
}
