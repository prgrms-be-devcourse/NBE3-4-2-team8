package com.ll.nbe342team8.domain.member.member.service;

import com.ll.nbe342team8.domain.member.deliveryInformation.entity.DeliveryInformation;
import com.ll.nbe342team8.domain.member.member.dto.PutReqMemberMyPageDto;
import com.ll.nbe342team8.domain.book.book.entity.Book;
import com.ll.nbe342team8.domain.book.review.entity.Review;
import com.ll.nbe342team8.domain.member.member.entity.Member;
import com.ll.nbe342team8.domain.member.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public Optional<Member> findByEmail(String email) {
        return memberRepository.findByEmail(email);
    }

    @Transactional
    public Member modifyOrJoin(String oauthId, PutReqMemberMyPageDto dto, String email) {
        return memberRepository.findByOauthId(oauthId) // 기존 회원인지 확인 (oauthId 기준으로 검색)
                .map(member -> {
                    // 기존 회원 정보 업데이트
                    member.updateMemberInfo(dto);
                    member.setEmail(email); // 이메일 업데이트 추가
                    return memberRepository.save(member);
                })
                .orElseGet(() -> {
                    // 새 회원 생성 시 기본값으로 USER 타입 설정
                    Member member = Member.builder()
                            .oauthId(oauthId)
                            .email(email)
                            .name(dto.getName())
                            .phoneNumber(dto.getPhoneNumber() != null ? dto.getPhoneNumber() : "")//전화번호가 없으면 빈 문자열("") 저장
                            .memberType(Member.MemberType.USER)
                            .build();
                    return memberRepository.save(member);
                });
    }


    public Member getMemberById(Long id){
        return memberRepository.findById(id).orElseThrow(() -> new IllegalArgumentException());
    }

    public Member create(Member member) {
        return memberRepository.save(member);
    }

    public long count(){
        return memberRepository.count();
    }

    public Optional<Member> findByOauthId(String oauthId) {
        return memberRepository.findByOauthId(oauthId);
    }
}
