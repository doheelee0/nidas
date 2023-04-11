package com.nidas.modules.account.validator;

import com.nidas.modules.account.IsAfter;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class IsAfterValidator implements ConstraintValidator<IsAfter, LocalDate> {

   private LocalDate date;

   @Override
   public void initialize(IsAfter constraintAnnotation) {
      this.date = LocalDate.parse(constraintAnnotation.date(), DateTimeFormatter.ofPattern("yyyy-MM-dd"));
   }

   @Override
   public boolean isValid(LocalDate value, ConstraintValidatorContext context) {
      if (value == null) return true;
      return value.isAfter(this.date);
   }
}
