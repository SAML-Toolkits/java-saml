package com.onelogin.saml2.model;

import java.util.List;

public class SubjectConfirmationIssue {
    private final int subjectConfirmationIndex;
    private final String message;

    public SubjectConfirmationIssue(int subjectConfirmationIndex, String message) {
        this.subjectConfirmationIndex = subjectConfirmationIndex;
        this.message = message;
    }

    public static String prettyPrintIssues(List<SubjectConfirmationIssue> subjectConfirmationDataIssues) {
        StringBuilder subjectConfirmationDataIssuesMsg = new StringBuilder("A valid SubjectConfirmation was not found on this Response");
        if (subjectConfirmationDataIssues.size() > 0) {
            subjectConfirmationDataIssuesMsg.append(": ");
        }
        for (int i = 0; i < subjectConfirmationDataIssues.size(); i++) {
            final SubjectConfirmationIssue issue = subjectConfirmationDataIssues.get(i);
            if (subjectConfirmationDataIssues.size() > 1) {
                subjectConfirmationDataIssuesMsg.append("\n[")
                        .append(issue.subjectConfirmationIndex)
                        .append("] ");
            }
            subjectConfirmationDataIssuesMsg.append(issue.message);
            if (i != subjectConfirmationDataIssues.size() - 1) {
                subjectConfirmationDataIssuesMsg.append(", ");
            }
        }

        return subjectConfirmationDataIssuesMsg.toString();
    }
}