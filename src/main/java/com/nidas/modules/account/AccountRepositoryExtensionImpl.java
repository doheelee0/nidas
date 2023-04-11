package com.nidas.modules.account;

import com.nidas.modules.account.form.AdminAccountSearchForm;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.QueryResults;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.time.LocalDate;

public class AccountRepositoryExtensionImpl extends QuerydslRepositorySupport implements AccountRepositoryExtension {

    QAccount account = QAccount.account;

    public AccountRepositoryExtensionImpl() {
        super(Account.class);
    }

    @Override
    public Page<Account> findByAdminAccountSearchForm(AdminAccountSearchForm adminAccountSearchForm, Pageable pageable) {
        BooleanBuilder builder = new BooleanBuilder();
        String[] keywordArray = adminAccountSearchForm.getKeywords().split("\\s+");
        for (String keyword : keywordArray) {
            builder.and(account.email.containsIgnoreCase(keyword).or(account.name.containsIgnoreCase(keyword)));
        }

        Gender gen = Gender.from(adminAccountSearchForm.getGender());
        if (gen != null) builder.and(account.gender.eq(gen));

        if (adminAccountSearchForm.isBirthdayOnToday()) builder.and(account.birthday.eq(LocalDate.now()));

        if (adminAccountSearchForm.isEmailVerified()) builder.and(account.emailVerified.isTrue());

        Membership mem = Membership.from(adminAccountSearchForm.getMembership());
        if (mem != null) builder.and(account.membership.eq(mem));

        if (adminAccountSearchForm.isNotDeleted()) builder.and(account.deleted.isFalse());

        JPQLQuery<Account> query = from(account)
                .where(builder)
                .orderBy(sort(adminAccountSearchForm.getSorting()));
        JPQLQuery<Account> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Account> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

    private OrderSpecifier sort(Sorting sorting) {
        OrderSpecifier orderSpecifier;
        switch (sorting) {
            case NAME:
                orderSpecifier = account.name.asc();
                break;
            case TOTAL_ORDER:
                orderSpecifier = account.totalOrder.desc();
                break;
            case TOTAL_PAYMENT:
                orderSpecifier = account.totalPayment.desc();
                break;
            case MEMBERSHIP:
                orderSpecifier = account.membership.desc();
                break;
            case LATEST_LOGIN_DATE_TIME:
                orderSpecifier = account.latestLoginDateTime.desc();
                break;
            case NEW_JOINED_DATE_TIME:
                orderSpecifier = account.joinedDateTime.desc();
                break;
            case OLD_JOINED_DATE_TIME:
                orderSpecifier = account.joinedDateTime.asc();
                break;
            default: // 기본값은 이메일순
                orderSpecifier = account.email.asc();
                break;
        }
        return orderSpecifier;
    }
}
