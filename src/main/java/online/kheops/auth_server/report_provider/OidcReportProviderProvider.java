package online.kheops.auth_server.report_provider;

import online.kheops.auth_server.entity.Album;
import online.kheops.auth_server.entity.Mutation;
import online.kheops.auth_server.entity.OidcReportProvider;
import online.kheops.auth_server.entity.OidcReportProviderParameter;
import online.kheops.auth_server.event.MutationType;
import online.kheops.auth_server.report_provider.metadata.Parameter;
import online.kheops.auth_server.report_provider.metadata.ParameterMap;

import javax.json.JsonValue;
import javax.persistence.EntityManager;

import static online.kheops.auth_server.album.Albums.getAlbum;
import static online.kheops.auth_server.event.Events.reportProviderMutation;

public class OidcReportProviderProvider {

  private final EntityManager entityManager;

  private OidcReportProviderProvider(EntityManager entityManager) {
    this.entityManager = entityManager;
  }

  public OidcReportProviderProvider newInstance(EntityManager entityManager) {
    return new OidcReportProviderProvider(entityManager);
  }

  public void insert(ParameterMap parameterMap) {

    final OidcReportProvider reportProvider = new OidcReportProvider();

    for (ParameterMap.Entry<?> entry: parameterMap.entrySet()) {
      final OidcReportProviderParameter parameterEntity = new OidcReportProviderParameter();
      parameterEntity.setName(entry.getKey().getKey());
      parameterEntity.setValue(entry.jsonValue().toString());
      parameterEntity.setReportProvider(reportProvider);

      entityManager.persist(parameterEntity);
      reportProvider.getParameters().add(parameterEntity);
    }
  }

  public ReportProvider get(String clientID) {
    return null;
  }
}
