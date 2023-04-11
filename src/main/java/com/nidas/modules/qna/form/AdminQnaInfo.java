package com.nidas.modules.qna.form;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.nidas.modules.qna.Qna;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter @Setter
public class AdminQnaInfo {

    private String productName;

    private String productThumbnail;

    private String type;

    private String content;

    private boolean secret;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDateTime createdDateTime;

    private boolean replied;

    public void setQnaInfo(Qna qna) {
        this.setProductName(qna.getProduct().getName());
        this.setProductThumbnail(qna.getProduct().getThumbnail());
        this.setType(qna.getType().getName());
        this.setContent(qna.getContent());
        this.setSecret(qna.isSecret());
        this.setCreatedDateTime(qna.getCreatedDateTime());
        this.setReplied(qna.getQnaReply() != null ? true : false);
    }
}