package com.nidas.modules.favorites;

import com.nidas.modules.account.Account;
import com.nidas.modules.account.CurrentAccount;
import com.nidas.modules.product.Product;
import com.nidas.modules.product.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class FavoritesRestController {

    private final FavoritesService favoritesService;
    private final ProductService productService;
    private final FavoritesRepository favoritesRepository;

    @PostMapping("/favorites/product/{id}/add")
    public ResponseEntity addFavorites(@PathVariable Long id, @CurrentAccount Account account) {
        Product product = productService.getProductToUpdateStatus(id);
        favoritesService.add(account, product);
        productService.updateFavoritesCount(product, true);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/favorites/product/{id}/remove")
    public ResponseEntity removeFavorites(@PathVariable Long id, @CurrentAccount Account account) {
        Product product = productService.getProductToUpdateStatus(id);
        favoritesService.remove(account, product);
        productService.updateFavoritesCount(product, false);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/favorites/product/{id}")
    public ResponseEntity getFavoritesAdded(@PathVariable Long id, @CurrentAccount Account account) {
        Product product = productService.getProductToUpdateStatus(id);
        boolean favoritesAdded = favoritesRepository.existsByAccountAndProduct(account, product);
        return ResponseEntity.ok().body(favoritesAdded);
    }

    @GetMapping("/favorites/products")
    public ResponseEntity getFavoritesAddedList(@CurrentAccount Account account) {
        List<Long> favoritesProductIdList = favoritesRepository.findFavoritesWithProductByAccount(account)
                .stream().map(favorites -> favorites.getProduct().getId()).collect(Collectors.toList());
        return ResponseEntity.ok().body(favoritesProductIdList);
    }

}
