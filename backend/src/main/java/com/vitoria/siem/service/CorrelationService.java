package com.vitoria.siem.service;

import com.vitoria.siem.model.Alert;
import com.vitoria.siem.repository.AlertRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CorrelationService {

    private static final Duration JANELA = Duration.ofMinutes(10);

    private final AlertRepository repository;

    public CorrelationService(AlertRepository repository) {
        this.repository = repository;
    }

    public void correlacionar(Alert novo) {
        // Ignora alertas do próprio SIEM e IPs que não conseguimos resolver
        if ("siem".equals(novo.getSource()) || "unknown".equals(novo.getSrcIp())) return;

        Instant desde = Instant.now().minus(JANELA);
        List<Alert> recentes = repository.findBySrcIpAndTimestampAfter(novo.getSrcIp(), desde);

        Set<String> fontes = recentes.stream()
                .map(Alert::getSource).collect(Collectors.toSet());
        Set<String> eventos = recentes.stream()
                .map(Alert::getEventType).collect(Collectors.toSet());

        // R001: NIDS + honeypot
        if (fontes.contains("nids") && fontes.contains("honeypot")) {
            gerar(novo.getSrcIp(), eventos, "multi_vector_attack", "R001",
                    "Mesmo IP no NIDS e no honeypot em 10 min", "\"T1046\",\"T1110\"");
        }

        // R002: phishing + (NIDS ou honeypot). So dispara quando o analisador de phishing estiver conectado
        if (fontes.contains("phishing")
                && (fontes.contains("nids") || fontes.contains("honeypot"))) {
            gerar(novo.getSrcIp(), eventos, "infrastructure_overlap", "R002",
                    "IP de site de phishing também atacou a rede em 10 min",
                    "\"T1566\",\"T1583\"");
        }
    }

    private void gerar(String ip, Set<String> eventosExistentes, String evento,
                       String regra, String descricao, String mitre) {
        if (eventosExistentes.contains(evento)) return;   // já gerado nesta janela

        Alert correlacionado = new Alert();
        correlacionado.setSource("siem");
        correlacionado.setTimestamp(Instant.now());
        correlacionado.setSrcIp(ip);
        correlacionado.setEventType(evento);
        correlacionado.setSeverity("high");
        correlacionado.setDetails("{\"rule\":\"" + regra + "\","
                + "\"description\":\"" + descricao + "\","
                + "\"mitre\":[" + mitre + "]}");
        repository.save(correlacionado);
    }
}
