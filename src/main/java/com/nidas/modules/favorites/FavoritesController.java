package com.nidas.modules.favorites;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.product.Product;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class FavoritesController {

    private final FavoritesRepository favoritesRepository;

    @GetMapping("/mypage/favorites-list")
    public String getFavoritesList(@CurrentAccount Account account, Model model) {
        List<Product> favoritesProductList = favoritesRepository.findFavoritesWithProductByAccount(account)
                .stream().map(Favorites::getProduct).collect(Collectors.toList());
        model.addAttribute("favoritesProductList", favoritesProductList);
        model.addAttribute(account);
        return "favorites/favorites-list";
    }

}
