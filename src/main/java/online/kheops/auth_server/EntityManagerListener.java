package online.kheops.auth_server;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.util.HashMap;
import java.util.Map;

@WebListener
public class EntityManagerListener implements ServletContextListener {
    private static EntityManagerFactory emf;

    @Override
    public void contextInitialized(ServletContextEvent event) {
        Map<String, String> properties = new HashMap<>();

        properties.put("javax.persistence.jdbc.user", event.getServletContext().getInitParameter("online.kheops.jdbc.user"));
        properties.put("javax.persistence.jdbc.password", event.getServletContext().getInitParameter("online.kheops.jdbc.password"));
        properties.put("javax.persistence.jdbc.url", event.getServletContext().getInitParameter("online.kheops.jdbc.url") + "?amp;characterEncoding=UTF-8");
//        properties.put("javax.persistence.jdbc.url", event.getServletContext().getInitParameter("online.kheops.jdbc.url") + "?useSSL=false&useUnicode=yes&amp;characterEncoding=UTF-8");

        emf = Persistence.createEntityManagerFactory("online.kheops", properties);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        emf.close();
    }

    public static EntityManager createEntityManager() {
        if (emf == null) {
            throw new IllegalStateException("Context is not initialized yet.");
        }
        return emf.createEntityManager();
    }
}
