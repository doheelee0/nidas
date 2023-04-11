package com.nidas.modules.cart.form;

import com.nidas.modules.product.Color;
import com.nidas.modules.product.Size;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.util.Objects;

@Getter @Setter
public class CartItemForm {

    @NotNull(message = "잘못된 색상입니다.")
    private Color color;

    @NotNull(message = "잘못된 사이즈입니다.")
    private Size size;

    @Min(value = 1, message = "최소 1개여야 합니다.")
    @Max(value = 9, message = "최대 9개여야 합니다.")
    private Integer quantity;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CartItemForm)) return false;
        CartItemForm cartItemForm = (CartItemForm) o;
        return color == cartItemForm.color && size == cartItemForm.size;
    }

    @Override
    public int hashCode() {
        return Objects.hash(color, size);
    }
}
