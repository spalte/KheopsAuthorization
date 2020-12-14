package online.kheops.auth_server.entity;


import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "oidc_report_providers")
public class OidcReportProvider {

  @Id
  @GeneratedValue(strategy= GenerationType.IDENTITY)
  @Column(name = "pk")
  private long pk;

  @Basic(optional = false)
  @Column(name = "creation_time")
  private LocalDateTime creationTime;

  @Basic(optional = false)
  @Column(name = "client_id", updatable = false)
  private String clientId;

  @Basic(optional = false)
  @Column(name = "name", updatable = false)
  private String name;

  @ManyToOne
  @JoinColumn (name = "album_fk", nullable=false, insertable = true, updatable = false)
  private Album album;

  @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.PERSIST, mappedBy = "reportProvider")
  private final Set<OidcReportProviderParameter> parameters = new HashSet<>();

  @PrePersist
  public void onPrePersist() {
    creationTime = LocalDateTime.now(ZoneOffset.UTC);
  }

  public Set<OidcReportProviderParameter> getParameters() {
    return parameters;
  }
}
