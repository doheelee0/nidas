package com.nidas.modules.favorites;

import com.nidas.infra.exception.ResourceNotFoundException;
import com.nidas.modules.account.Account;
import com.nidas.modules.product.Product;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class FavoritesService {

    private final FavoritesRepository favoritesRepository;

    public void add(Account account, Product product) {
        if (!favoritesRepository.existsByAccountAndProduct(account, product)) {
            favoritesRepository.save(Favorites.builder().account(account).product(product).build());
        }
    }

    public void remove(Account account, Product product) {
        Favorites favorites = favoritesRepository.findByAccountAndProduct(account, product);
        if (favorites == null) {
            throw new ResourceNotFoundException("삭제하려는 즐겨찾기가 존재하지 않습니다.");
        }
        favoritesRepository.delete(favorites);
    }

}
