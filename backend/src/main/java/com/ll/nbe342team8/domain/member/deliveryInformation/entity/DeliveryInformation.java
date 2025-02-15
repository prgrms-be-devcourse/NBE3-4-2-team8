package com.ll.nbe342team8.domain.member.deliveryInformation.entity;

import com.ll.nbe342team8.domain.member.deliveryInformation.dto.DeliveryInformationDto;
import com.ll.nbe342team8.domain.member.deliveryInformation.dto.ReqDeliveryInformationDto;
import com.ll.nbe342team8.domain.member.member.entity.Member;
import com.ll.nbe342team8.global.jpa.entity.BaseTime;
import com.ll.nbe342team8.standard.util.Ut;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeliveryInformation extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // AUTO_INCREMENT
    private Long id;

    private String addressName;

    private String postCode;

    private String detailAddress;

    private Boolean isDefaultAddress;

    private String recipient;

    private String phone;

    @ManyToOne(fetch = FetchType.LAZY)
    private Member member;

    public DeliveryInformation(ReqDeliveryInformationDto dto, Member member) {
        this.addressName = Ut.XSSSanitizer.sanitize(dto.addressName());
        this.postCode = Ut.XSSSanitizer.sanitize(dto.postCode());
        this.detailAddress = Ut.XSSSanitizer.sanitize(dto.detailAddress());
        this.recipient = Ut.XSSSanitizer.sanitize(dto.recipient());
        this.phone = Ut.XSSSanitizer.sanitize(dto.phone());
        this.isDefaultAddress=dto.isDefaultAddress();
        this.member=member;
    }

    public void updateDeliveryInfo(ReqDeliveryInformationDto dto) {
        this.addressName = Ut.XSSSanitizer.sanitize(dto.addressName());
        this.postCode = Ut.XSSSanitizer.sanitize(dto.postCode());
        this.detailAddress = Ut.XSSSanitizer.sanitize(dto.detailAddress());
        this.recipient = Ut.XSSSanitizer.sanitize(dto.recipient());
        this.phone = Ut.XSSSanitizer.sanitize(dto.phone());
        this.isDefaultAddress=dto.isDefaultAddress();

    }

}