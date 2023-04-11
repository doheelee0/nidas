package com.nidas.modules.qna;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class QnaReply {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private String content;

    private LocalDateTime createdDateTime;

}
