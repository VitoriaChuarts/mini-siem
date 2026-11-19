package com.vitoria.siem.service;

import com.vitoria.siem.model.Alert;
import com.vitoria.siem.repository.AlertRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CorrelationServiceTest {

    private static final String IP = "203.0.113.9";

    @Mock
    AlertRepository repository;

    @InjectMocks
    CorrelationService service;

    private Alert alerta(String source) {
        Alert a = new Alert();
        a.setSource(source);
        a.setSrcIp(IP);
        a.setTimestamp(Instant.now());
        return a;
    }

    @Test
    void geraAlertaQuandoMesmoIpApareceNoNidsENoHoneypot() {
        when(repository.findBySrcIpAndTimestampAfter(eq(IP), any()))
                .thenReturn(List.of(alerta("nids"), alerta("honeypot")));

        service.correlacionar(alerta("honeypot"));

        ArgumentCaptor<Alert> captor = ArgumentCaptor.forClass(Alert.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getSource()).isEqualTo("siem");
        assertThat(captor.getValue().getEventType()).isEqualTo("multi_vector_attack");
        assertThat(captor.getValue().getSeverity()).isEqualTo("high");
    }

    @Test
    void naoGeraAlertaQuandoHaApenasUmaFonte() {
        when(repository.findBySrcIpAndTimestampAfter(eq(IP), any()))
                .thenReturn(List.of(alerta("honeypot")));

        service.correlacionar(alerta("honeypot"));

        verify(repository, never()).save(any());
    }

    @Test
    void naoDuplicaAlertaCorrelacionadoRecente() {
        Alert jaGerado = alerta("siem");
        jaGerado.setEventType("multi_vector_attack");
        when(repository.findBySrcIpAndTimestampAfter(eq(IP), any()))
                .thenReturn(List.of(alerta("nids"), alerta("honeypot"), jaGerado));

        service.correlacionar(alerta("nids"));

        verify(repository, never()).save(any());
    }

    @Test
    void geraAlertaQuandoIpDoPhishingTambemAtacaARede() {
        when(repository.findBySrcIpAndTimestampAfter(eq(IP), any()))
                .thenReturn(List.of(alerta("phishing"), alerta("honeypot")));

        service.correlacionar(alerta("honeypot"));

        ArgumentCaptor<Alert> captor = ArgumentCaptor.forClass(Alert.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo("infrastructure_overlap");
        assertThat(captor.getValue().getSeverity()).isEqualTo("high");
    }

    @Test
    void ignoraAlertasGeradosPeloProprioSiem() {
        service.correlacionar(alerta("siem"));

        verifyNoInteractions(repository);
    }

    @Test
    void ignoraIpDesconhecido() {
        Alert phishing = alerta("phishing");
        phishing.setSrcIp("unknown");

        service.correlacionar(phishing);

        verifyNoInteractions(repository);
    }
}
