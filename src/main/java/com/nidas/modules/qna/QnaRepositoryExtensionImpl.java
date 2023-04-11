package com.nidas.modules.qna;

import com.nidas.modules.account.QAccount;
import com.nidas.modules.product.QProduct;
import com.nidas.modules.qna.form.AdminQnaSearchForm;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.QueryResults;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class QnaRepositoryExtensionImpl extends QuerydslRepositorySupport implements QnaRepositoryExtension {

    QQna qna = QQna.qna;

    public QnaRepositoryExtensionImpl() {
        super(Qna.class);
    }

    @Override
    public Page<Qna> findByAdminQnaSearchForm(AdminQnaSearchForm adminQnaSearchForm, Pageable pageable) {
        BooleanBuilder builder = new BooleanBuilder();

        builder.and(qna.account.email.containsIgnoreCase(adminQnaSearchForm.getEmail()));

        builder.and(qna.product.name.containsIgnoreCase(adminQnaSearchForm.getProductName()));

        List<QnaType> qnaTypeList = Arrays.stream(adminQnaSearchForm.getType().split(","))
                .filter(QnaType::contains)
                .map(q -> QnaType.valueOf(q.toUpperCase()))
                .collect(Collectors.toList());
        if (!qnaTypeList.isEmpty()) {
            builder.and(qna.type.in(qnaTypeList));
        }

        if (adminQnaSearchForm.isExceptReplied()) {
            builder.and(qna.qnaReply.isNull());
        }

        JPQLQuery<Qna> query = from(qna)
                .where(builder)
                .leftJoin(qna.account, QAccount.account).fetchJoin()
                .leftJoin(qna.product, QProduct.product).fetchJoin()
                .leftJoin(qna.qnaReply, QQnaReply.qnaReply).fetchJoin()
                .orderBy(qna.createdDateTime.desc());
        JPQLQuery<Qna> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Qna> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

}
