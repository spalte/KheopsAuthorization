package online.kheops.auth_server.event;

import online.kheops.auth_server.entity.Comment;
import online.kheops.auth_server.entity.Event;
import online.kheops.auth_server.entity.EventSeries;
import online.kheops.auth_server.entity.Mutation;
import online.kheops.auth_server.report_provider.ReportProviderResponse;
import online.kheops.auth_server.user.UserResponse;
import online.kheops.auth_server.user.UserResponseBuilder;

import javax.xml.bind.annotation.XmlElement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class EventResponse {

    private static class SeriesResponse {
        @XmlElement(name = "UID")
        private String seriesUID;
        @XmlElement(name = "description")
        private String seriesDescription;
    }

    private static class StudyResponse {
        @XmlElement(name = "UID")
        private String studyUID;
        @XmlElement(name = "description")
        private String studyDescription;
    }


    @XmlElement(name = "event_type")
    private String eventType;

    @XmlElement(name = "source")
    private UserResponse source;

    //Comment
    @XmlElement(name = "comment")
    private String comment;
    @XmlElement(name = "post_date")
    private LocalDateTime postDate;
    @XmlElement(name = "is_private")
    private Boolean privateComment;
    @XmlElement(name = "target")
    private UserResponse target;

    //Mutation
    @XmlElement(name = "mutation_type")
    private String mutationType;
    @XmlElement(name = "series")
    private SeriesResponse series;
    @XmlElement(name = "study")
    private StudyResponse study;
    @XmlElement(name = "report_provider")
    private ReportProviderResponse reportProvider;
    @XmlElement(name = "debug")
    private List<String> uidlst;

    private EventResponse() { /*empty*/ }

    public EventResponse(Event event, Map<String, Boolean> userMember) {
        if (event instanceof Comment) {
            this.commentEventResponse((Comment)event, userMember);
        } else if (event instanceof Mutation) {
            this.mutationEventResponse((Mutation) event, userMember);
        }
    }

    private void commentEventResponse(Comment comment, Map<String, Boolean> userMember) {

        eventType = "Comment";
        final UserResponseBuilder userResponseBuilder = new UserResponseBuilder()
                .setUser(comment.getUser())
                .setCanAccess(userMember.containsKey(comment.getUser().getSub()));
        if (comment.getAlbum() != null && userMember.containsKey(comment.getUser().getSub())) {
            userResponseBuilder.isAdmin(userMember.get(comment.getUser().getSub()));
        }
        source = userResponseBuilder.build();
        this.comment = comment.getComment();
        postDate = comment.getEventTime();
        if (comment.getPrivateTargetUser() != null) {
            privateComment = true;
            final UserResponseBuilder targetResponseBuilder = new UserResponseBuilder()
                    .setUser(comment.getPrivateTargetUser())
                    .setCanAccess(userMember.containsKey(comment.getPrivateTargetUser().getSub()));
            if (comment.getAlbum() != null && userMember.containsKey(comment.getPrivateTargetUser().getSub())) {
                targetResponseBuilder.isAdmin(userMember.get(comment.getPrivateTargetUser().getSub()));
            }
            target = targetResponseBuilder.build();
        } else {
            privateComment = false;
        }
    }

    private void mutationEventResponse(Mutation mutation, Map<String, Boolean> userMember) {

        eventType = "Mutation";

        final UserResponseBuilder userResponseBuilder = new UserResponseBuilder()
                .setUser(mutation.getUser())
                .setCanAccess(userMember.containsKey(mutation.getUser().getSub()));
        if (userMember.containsKey(mutation.getUser().getSub())) {
            userResponseBuilder.isAdmin(userMember.get(mutation.getUser().getSub()));
        }
        source = userResponseBuilder.build();
        postDate = mutation.getEventTime();
        mutationType = mutation.getMutationType().toString();
        final Events.MutationType mutationType_ = mutation.getMutationType();

        if (mutationType_.equals(Events.MutationType.PROMOTE_ADMIN) ||
                mutationType_.equals(Events.MutationType.DEMOTE_ADMIN) ||
                mutationType_.equals(Events.MutationType.ADD_USER) ||
                mutationType_.equals(Events.MutationType.ADD_ADMIN) ||
                mutationType_.equals(Events.MutationType.REMOVE_USER)) {
            final UserResponseBuilder targetUserResponseBuilder = new UserResponseBuilder()
                    .setUser(mutation.getToUser())
                    .setCanAccess(userMember.containsKey(mutation.getToUser().getSub()));
            if (userMember.containsKey(mutation.getToUser().getSub())) {
                targetUserResponseBuilder.isAdmin(userMember.get(mutation.getToUser().getSub()));
            }
            target = targetUserResponseBuilder.build();

        }
        if (mutationType_.equals(Events.MutationType.IMPORT_SERIES) ||
                mutationType_.equals(Events.MutationType.REMOVE_SERIES)) {
            series = new SeriesResponse();
            study = new StudyResponse();
            series.seriesUID = mutation.getSeries().getSeriesInstanceUID();
            series.seriesDescription = mutation.getSeries().getSeriesDescription();
            study.studyUID = mutation.getStudy().getStudyInstanceUID();
            study.studyDescription = mutation.getStudy().getStudyDescription();
            mutation.getReportProvider().ifPresent(mutationReportProvider ->
                    source.setReportProvider(mutationReportProvider, ReportProviderResponse.Type.EVENT));
        }
        if (mutationType_.equals(Events.MutationType.ADD_FAV) ||
                mutationType_.equals(Events.MutationType.REMOVE_FAV)) {
            if (mutation.getSeries() != null) {
                series = new SeriesResponse();
                series.seriesUID = mutation.getSeries().getSeriesInstanceUID();
                series.seriesDescription = mutation.getSeries().getSeriesDescription();
            }
            study = new StudyResponse();
            study.studyUID = mutation.getStudy().getStudyInstanceUID();
            study.studyDescription = mutation.getStudy().getStudyDescription();
        }
        if (mutationType_.equals(Events.MutationType.IMPORT_STUDY) ||
                mutationType_.equals(Events.MutationType.REMOVE_STUDY)) {
            study = new StudyResponse();
            study.studyUID = mutation.getStudy().getStudyInstanceUID();
            study.studyDescription = mutation.getStudy().getStudyDescription();
            uidlst = new ArrayList<>();
            for(EventSeries eventSeries : mutation.getEventSeries()) {
                uidlst.add(eventSeries.getSeries().getSeriesInstanceUID());
            }
        }

        if (mutationType_.equals(Events.MutationType.CREATE_REPORT_PROVIDER) ||
                mutationType_.equals(Events.MutationType.DELETE_REPORT_PROVIDER) ||
                mutationType_.equals(Events.MutationType.EDIT_REPORT_PROVIDER)) {
            mutation.getReportProvider().ifPresent(mutationReportProvider ->
                    reportProvider = new ReportProviderResponse(mutationReportProvider, ReportProviderResponse.Type.EVENT));
        }

        mutation.getCapability().ifPresent(mutationCapability -> source.setCapabilityToken(mutationCapability));
    }
}
