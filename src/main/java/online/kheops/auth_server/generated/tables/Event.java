/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated.tables;


import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Generated;

import online.kheops.auth_server.generated.Indexes;
import online.kheops.auth_server.generated.Keys;
import online.kheops.auth_server.generated.Kheops;
import online.kheops.auth_server.generated.tables.records.EventRecord;

import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.Identity;
import org.jooq.Index;
import org.jooq.Name;
import org.jooq.Record;
import org.jooq.Schema;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.TableImpl;


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
public class Event extends TableImpl<EventRecord> {

    private static final long serialVersionUID = 2051550633;

    /**
     * The reference instance of <code>kheops.event</code>
     */
    public static final Event EVENT = new Event();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<EventRecord> getRecordType() {
        return EventRecord.class;
    }

    /**
     * The column <code>kheops.event.pk</code>.
     */
    public final TableField<EventRecord, Long> PK = createField("pk", org.jooq.impl.SQLDataType.BIGINT.nullable(false).identity(true), this, "");

    /**
     * The column <code>kheops.event.event_type</code>.
     */
    public final TableField<EventRecord, String> EVENT_TYPE = createField("event_type", org.jooq.impl.SQLDataType.VARCHAR(255), this, "");

    /**
     * The column <code>kheops.event.album_fk</code>.
     */
    public final TableField<EventRecord, Long> ALBUM_FK = createField("album_fk", org.jooq.impl.SQLDataType.BIGINT, this, "");

    /**
     * The column <code>kheops.event.study_fk</code>.
     */
    public final TableField<EventRecord, Long> STUDY_FK = createField("study_fk", org.jooq.impl.SQLDataType.BIGINT, this, "");

    /**
     * The column <code>kheops.event.event_time</code>.
     */
    public final TableField<EventRecord, Timestamp> EVENT_TIME = createField("event_time", org.jooq.impl.SQLDataType.TIMESTAMP.nullable(false), this, "");

    /**
     * The column <code>kheops.event.user_fk</code>.
     */
    public final TableField<EventRecord, Long> USER_FK = createField("user_fk", org.jooq.impl.SQLDataType.BIGINT.nullable(false), this, "");

    /**
     * The column <code>kheops.event.private_target_user_fk</code>.
     */
    public final TableField<EventRecord, Long> PRIVATE_TARGET_USER_FK = createField("private_target_user_fk", org.jooq.impl.SQLDataType.BIGINT, this, "");

    /**
     * The column <code>kheops.event.comment</code>.
     */
    public final TableField<EventRecord, String> COMMENT = createField("comment", org.jooq.impl.SQLDataType.VARCHAR(1024), this, "");

    /**
     * The column <code>kheops.event.mutation_type</code>.
     */
    public final TableField<EventRecord, String> MUTATION_TYPE = createField("mutation_type", org.jooq.impl.SQLDataType.VARCHAR(255), this, "");

    /**
     * The column <code>kheops.event.to_user_fk</code>.
     */
    public final TableField<EventRecord, Long> TO_USER_FK = createField("to_user_fk", org.jooq.impl.SQLDataType.BIGINT, this, "");

    /**
     * The column <code>kheops.event.series_fk</code>.
     */
    public final TableField<EventRecord, Long> SERIES_FK = createField("series_fk", org.jooq.impl.SQLDataType.BIGINT, this, "");

    /**
     * Create a <code>kheops.event</code> table reference
     */
    public Event() {
        this(DSL.name("event"), null);
    }

    /**
     * Create an aliased <code>kheops.event</code> table reference
     */
    public Event(String alias) {
        this(DSL.name(alias), EVENT);
    }

    /**
     * Create an aliased <code>kheops.event</code> table reference
     */
    public Event(Name alias) {
        this(alias, EVENT);
    }

    private Event(Name alias, Table<EventRecord> aliased) {
        this(alias, aliased, null);
    }

    private Event(Name alias, Table<EventRecord> aliased, Field<?>[] parameters) {
        super(alias, null, aliased, parameters, DSL.comment(""));
    }

    public <O extends Record> Event(Table<O> child, ForeignKey<O, EventRecord> key) {
        super(child, key, EVENT);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Schema getSchema() {
        return Kheops.KHEOPS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Index> getIndexes() {
        return Arrays.<Index>asList(Indexes.EVENT_ALBUM_FK, Indexes.EVENT_PRIMARY, Indexes.EVENT_PRIVATE_TARGET_USER_FK, Indexes.EVENT_SERIES_FK, Indexes.EVENT_STUDY_FK, Indexes.EVENT_TO_USER_FK, Indexes.EVENT_USER_FK);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Identity<EventRecord, Long> getIdentity() {
        return Keys.IDENTITY_EVENT;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public UniqueKey<EventRecord> getPrimaryKey() {
        return Keys.KEY_EVENT_PRIMARY;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<UniqueKey<EventRecord>> getKeys() {
        return Arrays.<UniqueKey<EventRecord>>asList(Keys.KEY_EVENT_PRIMARY);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<ForeignKey<EventRecord, ?>> getReferences() {
        return Arrays.<ForeignKey<EventRecord, ?>>asList(Keys.EVENT_IBFK_1, Keys.EVENT_IBFK_2, Keys.EVENT_IBFK_3, Keys.EVENT_IBFK_5, Keys.EVENT_IBFK_4, Keys.EVENT_IBFK_6);
    }

    public Album album() {
        return new Album(this, Keys.EVENT_IBFK_1);
    }

    public Studies studies() {
        return new Studies(this, Keys.EVENT_IBFK_2);
    }

    public Users eventIbfk_3() {
        return new Users(this, Keys.EVENT_IBFK_3);
    }

    public Users eventIbfk_5() {
        return new Users(this, Keys.EVENT_IBFK_5);
    }

    public Users eventIbfk_4() {
        return new Users(this, Keys.EVENT_IBFK_4);
    }

    public Series series() {
        return new Series(this, Keys.EVENT_IBFK_6);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Event as(String alias) {
        return new Event(DSL.name(alias), this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Event as(Name alias) {
        return new Event(alias, this);
    }

    /**
     * Rename this table
     */
    @Override
    public Event rename(String name) {
        return new Event(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Event rename(Name name) {
        return new Event(name, null);
    }
}
