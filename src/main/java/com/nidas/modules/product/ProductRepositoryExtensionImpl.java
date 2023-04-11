package com.nidas.modules.product;

import com.nidas.modules.product.form.AdminProductSearchForm;
import com.nidas.modules.product.form.ProductSearchForm;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.QueryResults;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.Predicate;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class ProductRepositoryExtensionImpl extends QuerydslRepositorySupport implements ProductRepositoryExtension {

    QProduct product = QProduct.product;

    public ProductRepositoryExtensionImpl() {
        super(Product.class);
    }

    @Override
    public Page<Product> findByAdminProductSearchForm(Pageable pageable, AdminProductSearchForm adminProductSearchForm) {
        JPQLQuery<Product> query = from(product)
                .where(
                        containsKeyword(adminProductSearchForm.getKeywords()),
                        eqDiscount(adminProductSearchForm.isDiscount()),
                        eqSoldOut(adminProductSearchForm.isSoldOut()),
                        eqRecent(adminProductSearchForm.isRecent()),
                        inColor(adminProductSearchForm.getColor()),
                        eqDeleted(false)
                )
                .orderBy(sort(adminProductSearchForm.getSorting()));
        JPQLQuery<Product> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Product> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

    @Override
    public Page<Product> findByProductSearchForm(Pageable pageable, ProductSearchForm productSearchForm) {
        JPQLQuery<Product> query = from(product)
                .where(
                        containsKeyword(productSearchForm.getKeywords()),
                        eqCategory(productSearchForm.getMainCategory(), productSearchForm.getSubCategory()),
                        eqDiscount(productSearchForm.isDiscount()),
                        eqExceptSoldOut(productSearchForm.isExceptSoldOut()),
                        eqRecent(productSearchForm.isRecent()),
                        betweenPrice(productSearchForm.getMinPrice(), productSearchForm.getMaxPrice()),
                        inColor(productSearchForm.getColor()),
                        eqDeleted(false)
                )
                .orderBy(sort(productSearchForm.getSorting()));
        JPQLQuery<Product> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Product> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

    @Override
    public Page<Product> findByKeywords(Pageable pageable, String keywords, boolean deleted) {
        JPQLQuery<Product> query = from(product)
                .where(
                        containsKeyword(keywords),
                        eqDeleted(deleted)
                )
                .orderBy(product.name.asc());
        JPQLQuery<Product> pageableQuery = getQuerydsl().applyPagination(pageable, query);
        QueryResults<Product> fetchResults = pageableQuery.fetchResults();
        return new PageImpl<>(fetchResults.getResults(), pageable, fetchResults.getTotal());
    }

    private Predicate containsKeyword(String keywords) {
        return product.name.containsIgnoreCase(keywords);
    }

    private Predicate eqCategory(MainCategory mainCategory, SubCategory subCategory) {
        if (mainCategory == null) {
            return null;
        }
        if (subCategory == null) {
            return product.mainCategory.eq(mainCategory);
        }
        return product.mainCategory.eq(mainCategory).and(product.subCategory.eq(subCategory));
    }

    private Predicate eqDiscount(boolean discount) {
        return discount ? product.discountRate.gt(0) : null;
    }

    private Predicate eqSoldOut(boolean soldOut) { // 하위 상품들 중 하나라도 품절되었다면 선택
        return soldOut ? product.details.any().stock.eq(0) : null;
    }

    private Predicate eqExceptSoldOut(boolean exceptSoldOut) {
        return exceptSoldOut ? product.details.any().stock.gt(0) : null;
    }

    private Predicate eqRecent(boolean recent) {
        return recent ? product.createdDateTime.after(LocalDateTime.now().minusMonths(3)) : null;
    }

    private Predicate betweenPrice(Integer minPrice, Integer maxPrice) {
        BooleanBuilder builder = new BooleanBuilder();
        builder.and(product.price.goe(minPrice)).and(product.price.loe(maxPrice));
        return builder;
    }

    private Predicate inColor(String colorStr) {
        Set<Color> colorSet = Arrays.stream(colorStr.split(","))
                .filter(Color::contains)
                .map(color -> Color.valueOf(color.toUpperCase()))
                .collect(Collectors.toSet());
        return colorSet.isEmpty() ? null : product.details.any().color.in(colorSet);
    }

    private Predicate eqDeleted(boolean deleted) {
        return deleted ? product.deleted.isTrue() : product.deleted.isFalse();
    }

    private OrderSpecifier sort(Sorting sorting) {
        OrderSpecifier orderSpecifier;
        switch (sorting) {
            case REVIEW:
                orderSpecifier = product.reviewCount.desc();
                break;
            case RATING:
                orderSpecifier = product.rank.desc();
                break;
            case NAME:
                orderSpecifier = product.name.asc();
                break;
            case NEW:
                orderSpecifier = product.createdDateTime.desc();
                break;
            case OLD:
                orderSpecifier = product.createdDateTime.asc();
                break;
            case LOWER_PRICE:
                orderSpecifier = product.price.asc();
                break;
            case HIGH_PRICE:
                orderSpecifier = product.price.desc();
                break;
            case FAVORITES:
                orderSpecifier = product.favoritesCount.desc();
                break;
            default: // 기본값은 판매량순
                orderSpecifier = product.entireSalesQuantity.desc();
                break;
        }
        return orderSpecifier;
    }
}
