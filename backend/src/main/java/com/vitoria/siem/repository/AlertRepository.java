package com.vitoria.siem.repository;

import com.vitoria.siem.dto.Contagem;
import com.vitoria.siem.model.Alert;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findBySrcIpAndTimestampAfter(String srcIp, Instant since);

    @Query("SELECT new com.vitoria.siem.dto.Contagem(a.srcIp, COUNT(a)) FROM Alert a GROUP BY a.srcIp ORDER BY COUNT(a) DESC")
    List<Contagem> topIps(Pageable pageable);

    @Query("SELECT new com.vitoria.siem.dto.Contagem(a.severity, COUNT(a)) FROM Alert a GROUP BY a.severity")
    List<Contagem> contarPorSeveridade();

    @Query("SELECT new com.vitoria.siem.dto.Contagem(a.source, COUNT(a)) FROM Alert a GROUP BY a.source")
    List<Contagem> contarPorFonte();
}
