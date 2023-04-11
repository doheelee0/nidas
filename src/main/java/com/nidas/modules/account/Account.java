package com.nidas.modules.account;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Entity
@Getter @Setter @EqualsAndHashCode(of = "id")
@Builder @NoArgsConstructor @AllArgsConstructor
public class Account {

    @Id @GeneratedValue
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    private String emailCheckToken;

    private LocalDateTime emailCheckTokenGeneratedDateTime;

    private boolean emailVerified;

    @Column(nullable = false)
    private String password;

    private String passwordFindToken;

    private LocalDateTime passwordFindTokenGeneratedDateTime;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Gender gender;

    @Column(nullable = false, length = 8)
    private LocalDate birthday;

    @Column(nullable = false, length = 11)
    private String phoneNumber;

    private String address1;

    private String address2;

    private String address3;

    private Long totalPayment = 0L;

    private Integer totalOrder = 0;

    private Long mileage = 0L;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Membership membership = Membership.BRONZE;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Authority authority = Authority.ROLE_USER;

    private LocalDateTime joinedDateTime;

    private LocalDateTime latestLoginDateTime;

    private boolean receivingInfoByWeb = true;

    private boolean receivingInfoByEmail;

    private boolean deleted;

    public void generateEmailCheckToken() {
        this.emailCheckToken = UUID.randomUUID().toString();
        this.emailCheckTokenGeneratedDateTime = LocalDateTime.now();
    }

    public boolean isValidEmailCheckToken(String token) {
        return this.emailCheckToken.equals(token);
    }

    public void completeSignUp() {
        this.emailVerified = true;
        this.joinedDateTime = LocalDateTime.now();
    }

    public boolean canSendEmailCheckToken() {
        return LocalDateTime.now().isAfter(this.emailCheckTokenGeneratedDateTime.plusHours(1));
    }

    public long getEmailCheckTokenCoolTime() {
        return ChronoUnit.MINUTES.between(LocalDateTime.now(), this.emailCheckTokenGeneratedDateTime.plusHours(1));
    }

    public void generatePasswordFindToken() {
        this.passwordFindToken = UUID.randomUUID().toString();
        this.passwordFindTokenGeneratedDateTime = LocalDateTime.now();
    }

    public boolean isValidPasswordFindToken(String token) {
        return this.passwordFindToken != null && this.passwordFindToken.equals(token);
    }

    public void completePasswordFind() {
        this.passwordFindToken = null;
    }

    public boolean canSendPasswordFindToken() {
        return this.passwordFindTokenGeneratedDateTime == null
                || LocalDateTime.now().isAfter(this.passwordFindTokenGeneratedDateTime.plusHours(1));
    }

    public long getPasswordFindTokenCoolTime() {
        return ChronoUnit.MINUTES.between(LocalDateTime.now(), this.passwordFindTokenGeneratedDateTime.plusHours(1));
    }

    public boolean canOrder(Long mileageUsage) {
        return this.emailVerified && (this.mileage >= 0
                ? (mileageUsage >= 0 && this.mileage >= mileageUsage) : this.mileage.equals(mileageUsage));
    }

    public String getAnonymousEmail() {
        return this.email.substring(0, this.email.lastIndexOf("@") - 3).concat("***");
    }
}
