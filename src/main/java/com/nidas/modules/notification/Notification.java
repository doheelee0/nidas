package com.nidas.modules.notification;

import com.nidas.modules.account.Account;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
public class Notification {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private NotificationType type;

    private String link;

    @Column(nullable = false)
    private String message;

    private LocalDateTime createdDateTime;

    private boolean checked;

    @ManyToOne(fetch = FetchType.LAZY)
    private Account account;

}
