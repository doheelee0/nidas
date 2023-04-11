package com.nidas.modules.qna.event;

import com.nidas.modules.qna.Qna;
import lombok.Getter;

@Getter
public class QnaReplyEvent {

    private Qna qna;

    private String message;

    public QnaReplyEvent(Qna qna, String message) {
        this.qna = qna;
        this.message = message;
    }
}
