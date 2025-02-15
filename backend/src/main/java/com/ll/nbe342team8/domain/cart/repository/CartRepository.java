package com.ll.nbe342team8.domain.cart.repository;

import com.ll.nbe342team8.domain.book.book.entity.Book;
import com.ll.nbe342team8.domain.cart.entity.Cart;
import com.ll.nbe342team8.domain.member.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CartRepository extends JpaRepository<Cart, Long> {
    List<Cart> findAllByMember(Member member);
    
    Optional<Cart> findByMemberAndBook(Member member, Book book);

    void deleteByMember(Member member);
}
