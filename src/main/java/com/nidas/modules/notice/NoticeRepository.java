package com.nidas.modules.notice;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional(readOnly = true)
public interface NoticeRepository extends JpaRepository<Notice, Long> {

    Page<Notice> findByTitleContainingIgnoreCaseOrContentContainingIgnoreCase(String title, String content, Pageable pageable);

    List<Notice> findTop5ByOrderByCreatedDateTimeDesc();

}
