package com.nidas.modules.qna;

import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@NamedEntityGraph(
        name = "Qna.withQnaReplyAndAccount",
        attributeNodes = {
                @NamedAttributeNode(value = "qnaReply"),
                @NamedAttributeNode(value = "account")
        }
)

@NamedEntityGraph(
        name = "Qna.withQnaReplyAndProduct",
        attributeNodes = {
                @NamedAttributeNode(value = "qnaReply"),
                @NamedAttributeNode(value = "product")
        }
)

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Qna {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private QnaType type;

    private boolean secret;

    @Column(nullable = false)
    private String content;

    private LocalDateTime createdDateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    private Product product;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private QnaReply qnaReply;

}
