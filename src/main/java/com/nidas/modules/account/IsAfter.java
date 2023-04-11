package com.nidas.modules.account;

import com.nidas.modules.account.validator.IsAfterValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = IsAfterValidator.class)
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface IsAfter {

    String date() default "1900-01-01";
    String message() default "너무 과거의 값입니다.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

}
