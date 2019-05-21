/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated.tables.records;


import javax.annotation.Generated;

import online.kheops.auth_server.generated.tables.Version;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Row1;
import org.jooq.impl.TableRecordImpl;


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
public class VersionRecord extends TableRecordImpl<VersionRecord> implements Record1<String> {

    private static final long serialVersionUID = -1377512499;

    /**
     * Setter for <code>public.version.version</code>.
     */
    public void setVersion(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>public.version.version</code>.
     */
    public String getVersion() {
        return (String) get(0);
    }

    // -------------------------------------------------------------------------
    // Record1 type implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Row1<String> fieldsRow() {
        return (Row1) super.fieldsRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Row1<String> valuesRow() {
        return (Row1) super.valuesRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field1() {
        return Version.VERSION.VERSION_;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component1() {
        return getVersion();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value1() {
        return getVersion();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public VersionRecord value1(String value) {
        setVersion(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public VersionRecord values(String value1) {
        value1(value1);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached VersionRecord
     */
    public VersionRecord() {
        super(Version.VERSION);
    }

    /**
     * Create a detached, initialised VersionRecord
     */
    public VersionRecord(String version) {
        super(Version.VERSION);

        set(0, version);
    }
}