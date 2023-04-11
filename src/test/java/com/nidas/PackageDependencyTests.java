package com.nidas;

import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

@AnalyzeClasses(packagesOf = NidasApplication.class)
public class PackageDependencyTests {

    private static final String ACCOUNT = "..modules.account..";
    private static final String PRODUCT = "..modules.product..";
    private static final String CART = "..modules.cart..";
    private static final String FAVORITES = "..modules.favorites..";
    private static final String ORDER = "..modules.order..";
    private static final String REVIEW = "..modules.review..";
    private static final String RETURNS = "..modules.returns..";
    private static final String QNA = "..modules.qna..";
    private static final String MAIN = "..modules.main..";

    @ArchTest
    ArchRule productPackageRule = classes().that().resideInAPackage(PRODUCT)
            .should().onlyBeAccessed().byClassesThat()
            .resideInAnyPackage(PRODUCT, CART, FAVORITES, ORDER, REVIEW, RETURNS, QNA, MAIN);

    @ArchTest
    ArchRule accountPackageRule = classes().that().resideInAPackage(ACCOUNT)
            .should().accessClassesThat()
            .resideInAnyPackage(ACCOUNT);

    @ArchTest
    ArchRule cartPackageRule = classes().that().resideInAPackage(CART)
            .should().accessClassesThat()
            .resideInAnyPackage(CART, ACCOUNT, PRODUCT);

    @ArchTest
    ArchRule favoritesPackageRule = classes().that().resideInAPackage(FAVORITES)
            .should().accessClassesThat()
            .resideInAnyPackage(FAVORITES, ACCOUNT, PRODUCT);

    @ArchTest
    ArchRule orderPackageRule = classes().that().resideInAPackage(ORDER)
            .should().accessClassesThat()
            .resideInAnyPackage(ORDER, ACCOUNT, PRODUCT, CART);

    @ArchTest
    ArchRule reviewPackageRule = classes().that().resideInAPackage(REVIEW)
            .should().accessClassesThat()
            .resideInAnyPackage(REVIEW, ACCOUNT, PRODUCT, ORDER);

    @ArchTest
    ArchRule returnsPackageRule = classes().that().resideInAPackage(RETURNS)
            .should().accessClassesThat()
            .resideInAnyPackage(RETURNS, ACCOUNT, ORDER);

    @ArchTest
    ArchRule qnaPackageRule = classes().that().resideInAPackage(QNA)
            .should().accessClassesThat()
            .resideInAnyPackage(QNA, ACCOUNT, PRODUCT);

    @ArchTest
    ArchRule cycleCheck = slices().matching("com.nidas.modules.(*)..")
            .should().beFreeOfCycles();

}
