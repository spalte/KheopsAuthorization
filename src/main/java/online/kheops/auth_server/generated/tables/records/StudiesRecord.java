/*
 * This file is generated by jOOQ.
 */
package online.kheops.auth_server.generated.tables.records;


import java.sql.Timestamp;

import javax.annotation.Generated;

import online.kheops.auth_server.generated.tables.Studies;

import org.jooq.Field;
import org.jooq.Record1;
import org.jooq.Record15;
import org.jooq.Row15;
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
public class StudiesRecord extends UpdatableRecordImpl<StudiesRecord> implements Record15<Long, Timestamp, Timestamp, String, String, String, String, String, String, String, String, String, String, String, Byte> {

    private static final long serialVersionUID = 280991484;

    /**
     * Setter for <code>kheops.studies.pk</code>.
     */
    public void setPk(Long value) {
        set(0, value);
    }

    /**
     * Getter for <code>kheops.studies.pk</code>.
     */
    public Long getPk() {
        return (Long) get(0);
    }

    /**
     * Setter for <code>kheops.studies.created_time</code>.
     */
    public void setCreatedTime(Timestamp value) {
        set(1, value);
    }

    /**
     * Getter for <code>kheops.studies.created_time</code>.
     */
    public Timestamp getCreatedTime() {
        return (Timestamp) get(1);
    }

    /**
     * Setter for <code>kheops.studies.updated_time</code>.
     */
    public void setUpdatedTime(Timestamp value) {
        set(2, value);
    }

    /**
     * Getter for <code>kheops.studies.updated_time</code>.
     */
    public Timestamp getUpdatedTime() {
        return (Timestamp) get(2);
    }

    /**
     * Setter for <code>kheops.studies.study_uid</code>.
     */
    public void setStudyUid(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>kheops.studies.study_uid</code>.
     */
    public String getStudyUid() {
        return (String) get(3);
    }

    /**
     * Setter for <code>kheops.studies.study_date</code>.
     */
    public void setStudyDate(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>kheops.studies.study_date</code>.
     */
    public String getStudyDate() {
        return (String) get(4);
    }

    /**
     * Setter for <code>kheops.studies.study_time</code>.
     */
    public void setStudyTime(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>kheops.studies.study_time</code>.
     */
    public String getStudyTime() {
        return (String) get(5);
    }

    /**
     * Setter for <code>kheops.studies.timezone_offset_from_utc</code>.
     */
    public void setTimezoneOffsetFromUtc(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>kheops.studies.timezone_offset_from_utc</code>.
     */
    public String getTimezoneOffsetFromUtc() {
        return (String) get(6);
    }

    /**
     * Setter for <code>kheops.studies.accession_number</code>.
     */
    public void setAccessionNumber(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>kheops.studies.accession_number</code>.
     */
    public String getAccessionNumber() {
        return (String) get(7);
    }

    /**
     * Setter for <code>kheops.studies.referring_physician_name</code>.
     */
    public void setReferringPhysicianName(String value) {
        set(8, value);
    }

    /**
     * Getter for <code>kheops.studies.referring_physician_name</code>.
     */
    public String getReferringPhysicianName() {
        return (String) get(8);
    }

    /**
     * Setter for <code>kheops.studies.patient_name</code>.
     */
    public void setPatientName(String value) {
        set(9, value);
    }

    /**
     * Getter for <code>kheops.studies.patient_name</code>.
     */
    public String getPatientName() {
        return (String) get(9);
    }

    /**
     * Setter for <code>kheops.studies.patient_id</code>.
     */
    public void setPatientId(String value) {
        set(10, value);
    }

    /**
     * Getter for <code>kheops.studies.patient_id</code>.
     */
    public String getPatientId() {
        return (String) get(10);
    }

    /**
     * Setter for <code>kheops.studies.patient_birth_date</code>.
     */
    public void setPatientBirthDate(String value) {
        set(11, value);
    }

    /**
     * Getter for <code>kheops.studies.patient_birth_date</code>.
     */
    public String getPatientBirthDate() {
        return (String) get(11);
    }

    /**
     * Setter for <code>kheops.studies.patient_sex</code>.
     */
    public void setPatientSex(String value) {
        set(12, value);
    }

    /**
     * Getter for <code>kheops.studies.patient_sex</code>.
     */
    public String getPatientSex() {
        return (String) get(12);
    }

    /**
     * Setter for <code>kheops.studies.study_id</code>.
     */
    public void setStudyId(String value) {
        set(13, value);
    }

    /**
     * Getter for <code>kheops.studies.study_id</code>.
     */
    public String getStudyId() {
        return (String) get(13);
    }

    /**
     * Setter for <code>kheops.studies.populated</code>.
     */
    public void setPopulated(Byte value) {
        set(14, value);
    }

    /**
     * Getter for <code>kheops.studies.populated</code>.
     */
    public Byte getPopulated() {
        return (Byte) get(14);
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
    // Record15 type implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Row15<Long, Timestamp, Timestamp, String, String, String, String, String, String, String, String, String, String, String, Byte> fieldsRow() {
        return (Row15) super.fieldsRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Row15<Long, Timestamp, Timestamp, String, String, String, String, String, String, String, String, String, String, String, Byte> valuesRow() {
        return (Row15) super.valuesRow();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Long> field1() {
        return Studies.STUDIES.PK;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field2() {
        return Studies.STUDIES.CREATED_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Timestamp> field3() {
        return Studies.STUDIES.UPDATED_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field4() {
        return Studies.STUDIES.STUDY_UID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field5() {
        return Studies.STUDIES.STUDY_DATE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field6() {
        return Studies.STUDIES.STUDY_TIME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field7() {
        return Studies.STUDIES.TIMEZONE_OFFSET_FROM_UTC;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field8() {
        return Studies.STUDIES.ACCESSION_NUMBER;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field9() {
        return Studies.STUDIES.REFERRING_PHYSICIAN_NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field10() {
        return Studies.STUDIES.PATIENT_NAME;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field11() {
        return Studies.STUDIES.PATIENT_ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field12() {
        return Studies.STUDIES.PATIENT_BIRTH_DATE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field13() {
        return Studies.STUDIES.PATIENT_SEX;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<String> field14() {
        return Studies.STUDIES.STUDY_ID;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Field<Byte> field15() {
        return Studies.STUDIES.POPULATED;
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
    public String component4() {
        return getStudyUid();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component5() {
        return getStudyDate();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component6() {
        return getStudyTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component7() {
        return getTimezoneOffsetFromUtc();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component8() {
        return getAccessionNumber();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component9() {
        return getReferringPhysicianName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component10() {
        return getPatientName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component11() {
        return getPatientId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component12() {
        return getPatientBirthDate();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component13() {
        return getPatientSex();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String component14() {
        return getStudyId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Byte component15() {
        return getPopulated();
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
    public String value4() {
        return getStudyUid();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value5() {
        return getStudyDate();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value6() {
        return getStudyTime();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value7() {
        return getTimezoneOffsetFromUtc();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value8() {
        return getAccessionNumber();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value9() {
        return getReferringPhysicianName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value10() {
        return getPatientName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value11() {
        return getPatientId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value12() {
        return getPatientBirthDate();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value13() {
        return getPatientSex();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String value14() {
        return getStudyId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Byte value15() {
        return getPopulated();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value1(Long value) {
        setPk(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value2(Timestamp value) {
        setCreatedTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value3(Timestamp value) {
        setUpdatedTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value4(String value) {
        setStudyUid(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value5(String value) {
        setStudyDate(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value6(String value) {
        setStudyTime(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value7(String value) {
        setTimezoneOffsetFromUtc(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value8(String value) {
        setAccessionNumber(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value9(String value) {
        setReferringPhysicianName(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value10(String value) {
        setPatientName(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value11(String value) {
        setPatientId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value12(String value) {
        setPatientBirthDate(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value13(String value) {
        setPatientSex(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value14(String value) {
        setStudyId(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord value15(Byte value) {
        setPopulated(value);
        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StudiesRecord values(Long value1, Timestamp value2, Timestamp value3, String value4, String value5, String value6, String value7, String value8, String value9, String value10, String value11, String value12, String value13, String value14, Byte value15) {
        value1(value1);
        value2(value2);
        value3(value3);
        value4(value4);
        value5(value5);
        value6(value6);
        value7(value7);
        value8(value8);
        value9(value9);
        value10(value10);
        value11(value11);
        value12(value12);
        value13(value13);
        value14(value14);
        value15(value15);
        return this;
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached StudiesRecord
     */
    public StudiesRecord() {
        super(Studies.STUDIES);
    }

    /**
     * Create a detached, initialised StudiesRecord
     */
    public StudiesRecord(Long pk, Timestamp createdTime, Timestamp updatedTime, String studyUid, String studyDate, String studyTime, String timezoneOffsetFromUtc, String accessionNumber, String referringPhysicianName, String patientName, String patientId, String patientBirthDate, String patientSex, String studyId, Byte populated) {
        super(Studies.STUDIES);

        set(0, pk);
        set(1, createdTime);
        set(2, updatedTime);
        set(3, studyUid);
        set(4, studyDate);
        set(5, studyTime);
        set(6, timezoneOffsetFromUtc);
        set(7, accessionNumber);
        set(8, referringPhysicianName);
        set(9, patientName);
        set(10, patientId);
        set(11, patientBirthDate);
        set(12, patientSex);
        set(13, studyId);
        set(14, populated);
    }
}
