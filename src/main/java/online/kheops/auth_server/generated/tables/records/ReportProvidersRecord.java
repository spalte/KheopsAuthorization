/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated.tables.records;


import java.sql.Timestamp;

import javax.annotation.Generated;

import online.kheops.auth_server.generated.tables.ReportProviders;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record7;
import org.jooq.Row7;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@Generated(
    value = {
        "http://www.jooq.org",
        "jOOQ version:3.11.2"
    },
    comments = "This class is generated by jOOQ"
)
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class ReportProvidersRecord extends UpdatableRecordImpl<ReportProvidersRecord> implements Record7<Long, Long, Timestamp, String, String, String, Boolean> {

    private static final long serialVersionUID = 1123357179;

    /**
     * Setter for <code>public.report_providers.pk</code>.
     */
    public void setPk(Long value) {
        set(0, value);
    }

    /**
     * Getter for <code>public.report_providers.pk</code>.
     */
    public Long getPk() {
        return (Long) get(0);
    }

    /**
     * Setter for <code>public.report_providers.album_fk</code>.
     */
    public void setAlbumFk(Long value) {
        set(1, value);
    }

    /**
     * Getter for <code>public.report_providers.album_fk</code>.
     */
    public Long getAlbumFk() {
        return (Long) get(1);
    }

    /**
     * Setter for <code>public.report_providers.creation_time</code>.
     */
    public void setCreationTime(Timestamp value) {
        set(2, value);
    }

    /**
     * Getter for <code>public.report_providers.creation_time</code>.
     */
    public Timestamp getCreationTime() {
        return (Timestamp) get(2);
    }

    /**
     * Setter for <code>public.report_providers.name</code>.
     */
    public void setName(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>public.report_providers.name</code>.
     */
    public String getName() {
        return (String) get(3);
    }

    /**
     * Setter for <code>public.report_providers.url</code>.
     */
    public void setUrl(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>public.report_providers.url</code>.
     */
    public String getUrl() {
        return (String) get(4);
    }

    /**
     * Setter for <code>public.report_providers.client_id</code>.
     */
    public void setClientId(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>public.report_providers.client_id</code>.
     */
    public String getClientId() {
        return (String) get(5);
    }

    /**
     * Setter for <code>public.report_providers.removed</code>.
     */
    public void setRemoved(Boolean value) {
        set(6, value);
    }

    /**
     * Getter for <code>public.report_providers.removed</code>.
     */
    public Boolean getRemoved() {
        return (Boolean) get(6);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Record1<Long> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Record7 type implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Row7<Long, Long, Timestamp, String, String, String, Boolean> fieldsRow() {
        return (Row7) super.fieldsRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Row7<Long, Long, Timestamp, String, String, String, Boolean> valuesRow() {
        return (Row7) super.valuesRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Long> field1() {
        return ReportProviders.REPORT_PROVIDERS.PK;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Long> field2() {
        return ReportProviders.REPORT_PROVIDERS.ALBUM_FK;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field3() {
        return ReportProviders.REPORT_PROVIDERS.CREATION_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field4() {
        return ReportProviders.REPORT_PROVIDERS.NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field5() {
        return ReportProviders.REPORT_PROVIDERS.URL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field6() {
        return ReportProviders.REPORT_PROVIDERS.CLIENT_ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Boolean> field7() {
        return ReportProviders.REPORT_PROVIDERS.REMOVED;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long component1() {
        return getPk();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long component2() {
        return getAlbumFk();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp component3() {
        return getCreationTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component4() {
        return getName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component5() {
        return getUrl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component6() {
        return getClientId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean component7() {
        return getRemoved();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long value1() {
        return getPk();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long value2() {
        return getAlbumFk();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp value3() {
        return getCreationTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value4() {
        return getName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value5() {
        return getUrl();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value6() {
        return getClientId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean value7() {
        return getRemoved();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value1(Long value) {
        setPk(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value2(Long value) {
        setAlbumFk(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value3(Timestamp value) {
        setCreationTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value4(String value) {
        setName(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value5(String value) {
        setUrl(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value6(String value) {
        setClientId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord value7(Boolean value) {
        setRemoved(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ReportProvidersRecord values(Long value1, Long value2, Timestamp value3, String value4, String value5, String value6, Boolean value7) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        value6(value6);
        value7(value7);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached ReportProvidersRecord
     */
    public ReportProvidersRecord() {
        super(ReportProviders.REPORT_PROVIDERS);
    }

    /**
     * Create a detached, initialised ReportProvidersRecord
     */
    public ReportProvidersRecord(Long pk, Long albumFk, Timestamp creationTime, String name, String url, String clientId, Boolean removed) {
        super(ReportProviders.REPORT_PROVIDERS);

        set(0, pk);
        set(1, albumFk);
        set(2, creationTime);
        set(3, name);
        set(4, url);
        set(5, clientId);
        set(6, removed);
    }
}
