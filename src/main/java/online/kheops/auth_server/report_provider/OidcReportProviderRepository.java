package online.kheops.auth_server.report_provider;

import online.kheops.auth_server.entity.OidcReportProvider;
import online.kheops.auth_server.entity.OidcReportProviderParameter;
import online.kheops.auth_server.report_provider.metadata.ParameterMap;

import javax.persistence.EntityManager;

import static online.kheops.auth_server.album.Albums.getAlbum;

public class OidcReportProviderRepository {

  private final EntityManager entityManager;

  private OidcReportProviderRepository(EntityManager entityManager) {
    this.entityManager = entityManager;
  }

  public static OidcReportProviderRepository newInstance(EntityManager entityManager) {
    return new OidcReportProviderRepository(entityManager);
  }

  public ReportProvider insert(ParameterMap parameterMap) {

    final OidcReportProvider reportProvider = new OidcReportProvider();

    for (ParameterMap.Entry<?> entry: parameterMap.entrySet()) {
      final OidcReportProviderParameter parameterEntity = new OidcReportProviderParameter();
      parameterEntity.setName(entry.getKey().getKey());
      parameterEntity.setValue(entry.jsonValue().toString());
      parameterEntity.setReportProvider(reportProvider);

      entityManager.persist(parameterEntity);
      reportProvider.getParameters().add(parameterEntity);
    }

    entityManager.flush();


  }

  public ReportProvider get(String clientID) {
    return null;
  }
}
