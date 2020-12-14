package online.kheops.auth_server.entity;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Entity
@Table(name = "report_provider_metadata")
public class OidcReportProviderParameter {

  @Id
  @GeneratedValue(strategy= GenerationType.IDENTITY)
  @Column(name = "pk")
  private long pk;

  @Basic(optional = false)
  @Column(name = "creation_time")
  private LocalDateTime creationTime;

  @Basic(optional = false)
  @Column(name = "name")
  private String name;

  @Basic(optional = false)
  @Column(name = "value")
  private String value;

  @ManyToOne
  @JoinColumn (name = "report_provider_fk", nullable=false, updatable = false)
  private OidcReportProvider reportProvider;

  @PrePersist
  public void onPrePersist() {
    creationTime = LocalDateTime.now(ZoneOffset.UTC);
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public OidcReportProvider getReportProvider() {
    return reportProvider;
  }

  public void setReportProvider(OidcReportProvider reportProvider) {
    this.reportProvider = reportProvider;
  }
}
