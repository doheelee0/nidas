package com.nidas.modules.qna.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.account.Account;
import com.nidas.modules.qna.Qna;
import com.nidas.modules.qna.QnaReply;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter @Setter
public class QnaForm {

    private String type;

    private String content;

    private boolean secret;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy.MM.dd")
    private LocalDateTime createdDateTime;

    private String email;

    private boolean answered;

    private String replyContent;

    private boolean hasNotPermission;

    public void setQna(Qna qna, Account myAccount) {
        Account account = qna.getAccount();
        QnaReply qnaReply = qna.getQnaReply();
        boolean hasNotPermission = qna.isSecret() && !account.equals(myAccount);

        this.type = qna.getType().getName();
        this.content = hasNotPermission ? "" : qna.getContent();
        this.secret = qna.isSecret();
        this.createdDateTime = qna.getCreatedDateTime();
        this.email = account.getAnonymousEmail();
        this.answered = qnaReply != null ? true : false;
        this.replyContent = qnaReply != null && !hasNotPermission ? qnaReply.getContent() : "";
        this.hasNotPermission = hasNotPermission;
    }
}
