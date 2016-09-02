package com.onelogin.saml2.authn;

import java.util.List;

class SubjectConfirmationIssue {
    private final int subjectConfirmationIndex;
    private final String message;

    SubjectConfirmationIssue(int subjectConfirmationIndex, String message) {
        this.subjectConfirmationIndex = subjectConfirmationIndex;
        this.message = message;
    }

    static String prettyPrint(List<SubjectConfirmationIssue> subjectConfirmationDataIssues) {
        StringBuilder subjectConfirmationDataIssuesMsg = new StringBuilder("A valid SubjectConfirmation was not found on this Response");
        if (subjectConfirmationDataIssues.size() > 0) {
            subjectConfirmationDataIssuesMsg.append(" - ");
        }
        for (int i = 0; i < subjectConfirmationDataIssues.size(); i++) {
            final SubjectConfirmationIssue issue = subjectConfirmationDataIssues.get(i);
            subjectConfirmationDataIssuesMsg.append(issue.message);
            if (subjectConfirmationDataIssues.size() > 1) {
                subjectConfirmationDataIssuesMsg.append(" [")
                        .append(issue.subjectConfirmationIndex)
                        .append("]");
            }
            if (i != subjectConfirmationDataIssues.size() - 1) {
                subjectConfirmationDataIssuesMsg.append(", ");
            }
        }

        return subjectConfirmationDataIssuesMsg.toString();
    }
}