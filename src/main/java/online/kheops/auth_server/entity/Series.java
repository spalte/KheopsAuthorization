package online.kheops.auth_server.entity;

import org.dcm4che3.data.Attributes;
import org.dcm4che3.data.Tag;
import org.dcm4che3.data.VR;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

@SuppressWarnings({"WeakerAccess", "unused"})
@Entity
@Table(name = "series")
public class Series {
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    @Column(name = "pk")
    private long pk;

    @Basic(optional = false)
    @Column(name = "created_time", updatable = false)
    private LocalDateTime createdTime;

    @Basic(optional = false)
    @Column(name = "updated_time")
    private LocalDateTime updatedTime;

    @Basic(optional = false)
    @Column(name = "series_uid", updatable = false)
    private String seriesInstanceUID;

    @Column(name = "modality")
    private String modality;

    @Column(name = "timezone_offset_from_utc")
    private String timezoneOffsetFromUTC;

    @Column(name = "series_description")
    private String seriesDescription;

    @Column(name = "series_number")
    private int seriesNumber;

    @Column(name = "number_of_series_related_instances")
    private int numberOfSeriesRelatedInstances;

    @Basic(optional = false)
    @Column(name = "populated")
    private boolean populated = false;

    @ManyToOne
    @JoinColumn(name = "study_fk", insertable=false, updatable=false)
    private Study study;

    @ManyToMany(mappedBy = "series")
    private Set<User> users = new HashSet<>();

    public Series() {}

    public Series(String newSeriesInstanceUID) {
        seriesInstanceUID = newSeriesInstanceUID;
    }

    @PrePersist
    public void onPrePersist() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        createdTime = now;
        updatedTime = now;
    }

    @PreUpdate
    public void onPreUpdate() {
        updatedTime = LocalDateTime.now(ZoneOffset.UTC);
    }

    public Attributes getAttributes() {
        if (!isPopulated()) {
            throw new IllegalStateException();
        }

        Attributes attributes = new Attributes();

        safeAttributeSetString(attributes, Tag.Modality, VR.CS, getModality());
        safeAttributeSetString(attributes, Tag.TimezoneOffsetFromUTC, VR.SH, getTimezoneOffsetFromUTC());
        safeAttributeSetString(attributes, Tag.SeriesDescription, VR.LO, getSeriesDescription());

        attributes.setInt(Tag.SeriesNumber, VR.IS, getSeriesNumber());
        attributes.setInt(Tag.NumberOfSeriesRelatedInstances, VR.IS, getNumberOfSeriesRelatedInstances());

        return attributes;
    }

    private void safeAttributeSetString(Attributes attributes, int tag, VR vr, String string) {
        if (string != null) {
            attributes.setString(tag, vr, string);
        }
    }

    // doesn't set populated, but the caller probably will want to set populated after calling this method
    public void mergeAttributes(Attributes attributes) {
        setModality(attributes.getString(Tag.Modality, getModality()));
        setSeriesDescription(attributes.getString(Tag.SeriesDescription, getSeriesDescription()));
        setTimezoneOffsetFromUTC(attributes.getString(Tag.TimezoneOffsetFromUTC, getTimezoneOffsetFromUTC()));
        setSeriesNumber(attributes.getInt(Tag.SeriesNumber, getSeriesNumber()));
        setNumberOfSeriesRelatedInstances(attributes.getInt(Tag.NumberOfSeriesRelatedInstances, getNumberOfSeriesRelatedInstances()));
    }

    public long getPk() {
        return pk;
    }

    public LocalDateTime getCreatedTime() {
        return createdTime;
    }

    public LocalDateTime getUpdatedTime() {
        return updatedTime;
    }

    public String getSeriesInstanceUID() {
        return seriesInstanceUID;
    }

    public String getModality() {
        return modality;
    }

    public void setModality(String modality) {
        this.modality = modality;
    }

    public Study getStudy() {
        return study;
    }

    public void setStudy(Study study) {
        this.study = study;
    }

    public boolean isPopulated() {
        return populated;
    }

    public void setPopulated(boolean populated) {
        this.populated = populated;
    }

    public String getTimezoneOffsetFromUTC() {
        return timezoneOffsetFromUTC;
    }

    public void setTimezoneOffsetFromUTC(String timezoneOffsetFromUTC) {
        this.timezoneOffsetFromUTC = timezoneOffsetFromUTC;
    }

    public String getSeriesDescription() {
        return seriesDescription;
    }

    public void setSeriesDescription(String seriesDescription) {
        this.seriesDescription = seriesDescription;
    }

    public int getSeriesNumber() {
        return seriesNumber;
    }

    public void setSeriesNumber(int seriesNumber) {
        this.seriesNumber = seriesNumber;
    }

    public int getNumberOfSeriesRelatedInstances() {
        return numberOfSeriesRelatedInstances;
    }

    public void setNumberOfSeriesRelatedInstances(int numberOfSeriesRelatedInstances) {
        this.numberOfSeriesRelatedInstances = numberOfSeriesRelatedInstances;
    }

    public Set<User> getUsers() {
        return users;
    }
}
