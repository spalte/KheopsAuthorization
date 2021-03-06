/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated.tables.records;


import java.sql.Timestamp;

import javax.annotation.Generated;

import online.kheops.auth_server.generated.tables.Capabilities;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record8;
import org.jooq.Row8;
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
public class CapabilitiesRecord extends UpdatableRecordImpl<CapabilitiesRecord> implements Record8<Long, Timestamp, Timestamp, Timestamp, Timestamp, String, String, Long> {

    private static final long serialVersionUID = -1318110361;

    /**
     * Setter for <code>kheops.capabilities.pk</code>.
     */
    public void setPk(Long value) {
        set(0, value);
    }

    /**
     * Getter for <code>kheops.capabilities.pk</code>.
     */
    public Long getPk() {
        return (Long) get(0);
    }

    /**
     * Setter for <code>kheops.capabilities.created_time</code>.
     */
    public void setCreatedTime(Timestamp value) {
        set(1, value);
    }

    /**
     * Getter for <code>kheops.capabilities.created_time</code>.
     */
    public Timestamp getCreatedTime() {
        return (Timestamp) get(1);
    }

    /**
     * Setter for <code>kheops.capabilities.updated_time</code>.
     */
    public void setUpdatedTime(Timestamp value) {
        set(2, value);
    }

    /**
     * Getter for <code>kheops.capabilities.updated_time</code>.
     */
    public Timestamp getUpdatedTime() {
        return (Timestamp) get(2);
    }

    /**
     * Setter for <code>kheops.capabilities.expiration_time</code>.
     */
    public void setExpirationTime(Timestamp value) {
        set(3, value);
    }

    /**
     * Getter for <code>kheops.capabilities.expiration_time</code>.
     */
    public Timestamp getExpirationTime() {
        return (Timestamp) get(3);
    }

    /**
     * Setter for <code>kheops.capabilities.revoked_time</code>.
     */
    public void setRevokedTime(Timestamp value) {
        set(4, value);
    }

    /**
     * Getter for <code>kheops.capabilities.revoked_time</code>.
     */
    public Timestamp getRevokedTime() {
        return (Timestamp) get(4);
    }

    /**
     * Setter for <code>kheops.capabilities.description</code>.
     */
    public void setDescription(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>kheops.capabilities.description</code>.
     */
    public String getDescription() {
        return (String) get(5);
    }

    /**
     * Setter for <code>kheops.capabilities.secret</code>.
     */
    public void setSecret(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>kheops.capabilities.secret</code>.
     */
    public String getSecret() {
        return (String) get(6);
    }

    /**
     * Setter for <code>kheops.capabilities.user_fk</code>.
     */
    public void setUserFk(Long value) {
        set(7, value);
    }

    /**
     * Getter for <code>kheops.capabilities.user_fk</code>.
     */
    public Long getUserFk() {
        return (Long) get(7);
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
    // Record8 type implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Row8<Long, Timestamp, Timestamp, Timestamp, Timestamp, String, String, Long> fieldsRow() {
        return (Row8) super.fieldsRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Row8<Long, Timestamp, Timestamp, Timestamp, Timestamp, String, String, Long> valuesRow() {
        return (Row8) super.valuesRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Long> field1() {
        return Capabilities.CAPABILITIES.PK;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field2() {
        return Capabilities.CAPABILITIES.CREATED_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field3() {
        return Capabilities.CAPABILITIES.UPDATED_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field4() {
        return Capabilities.CAPABILITIES.EXPIRATION_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field5() {
        return Capabilities.CAPABILITIES.REVOKED_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field6() {
        return Capabilities.CAPABILITIES.DESCRIPTION;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field7() {
        return Capabilities.CAPABILITIES.SECRET;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Long> field8() {
        return Capabilities.CAPABILITIES.USER_FK;
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
    public Timestamp component2() {
        return getCreatedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp component3() {
        return getUpdatedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp component4() {
        return getExpirationTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp component5() {
        return getRevokedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component6() {
        return getDescription();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component7() {
        return getSecret();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long component8() {
        return getUserFk();
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
    public Timestamp value2() {
        return getCreatedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp value3() {
        return getUpdatedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp value4() {
        return getExpirationTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Timestamp value5() {
        return getRevokedTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value6() {
        return getDescription();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value7() {
        return getSecret();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Long value8() {
        return getUserFk();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value1(Long value) {
        setPk(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value2(Timestamp value) {
        setCreatedTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value3(Timestamp value) {
        setUpdatedTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value4(Timestamp value) {
        setExpirationTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value5(Timestamp value) {
        setRevokedTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value6(String value) {
        setDescription(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value7(String value) {
        setSecret(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord value8(Long value) {
        setUserFk(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CapabilitiesRecord values(Long value1, Timestamp value2, Timestamp value3, Timestamp value4, Timestamp value5, String value6, String value7, Long value8) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        value6(value6);
        value7(value7);
        value8(value8);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached CapabilitiesRecord
     */
    public CapabilitiesRecord() {
        super(Capabilities.CAPABILITIES);
    }

    /**
     * Create a detached, initialised CapabilitiesRecord
     */
    public CapabilitiesRecord(Long pk, Timestamp createdTime, Timestamp updatedTime, Timestamp expirationTime, Timestamp revokedTime, String description, String secret, Long userFk) {
        super(Capabilities.CAPABILITIES);

        set(0, pk);
        set(1, createdTime);
        set(2, updatedTime);
        set(3, expirationTime);
        set(4, revokedTime);
        set(5, description);
        set(6, secret);
        set(7, userFk);
    }
}
